//! The serverless replica engine (workstream **d3**).
//!
//! Every member runs a replica. The group chat is an ordered log of [`Record`]s;
//! each replica ingests it, applies the same deterministic accept rule, and
//! thereby computes the same bulletin. *The accept rule is the protocol*
//! (`docs/SERVERLESS_PROTOCOL.md` §1). This module is that rule, and the state it
//! maintains: the d1 Merkle object and callback trees, the nullifier set, the
//! poll/rating tallies, the outstanding-ticket settlement set, and the persona
//! cache — all derived from the log, none of it trusted from a peer.
//!
//! # Why it recomputes rather than mutates forward
//!
//! Convergence (§1) is the whole game: two replicas that have ingested the *same*
//! records must compute the *same* roots, or they have forked. Arrival order is
//! adversarial — the messenger may deliver a member's second post before their
//! first — so the engine cannot simply append as records land. The d1 object tree
//! is append-*order*-sensitive (d1 §assumption 5 punts the ordering to here), so a
//! convergent replica must impose a **canonical** order independent of arrival.
//!
//! The canonical order is §4's: **prefix (causal) order, tiebroken by ascending
//! envelope hash.** A record names the object root it was built on (§5.1), which
//! is a commitment to the prefix accepted before it, so "root `r` was produced" is
//! the causal predicate and the smaller `eh` wins a genuine tie. The engine
//! realises this by *replaying the whole seen set* on each change: at each barrier
//! it repeatedly applies the smallest-`eh` record whose named root it has already
//! produced, until none remain. This is a deterministic function of (the record
//! set, the per-record first-seen barrier, the current barrier) — so replicas that
//! saw the same records under the same barrier schedule converge exactly, and the
//! rest converge as the schedule catches up (§5.2's transient-then-closed
//! divergence). Groth16 verification is memoised by `eh` (a proof's validity
//! against the root it names is a fixed fact), so replay costs one verification per
//! record, not one per rebuild.
//!
//! Replaying from genesis on every change is quadratic in practice: the cost grows with
//! (records × barriers), and the messenger rebuilds on every ingest *and* every
//! heartbeat. So the rebuild is checkpointed: the state at the end of each recent
//! barrier is kept, and a change replays only from the first barrier it can affect —
//! a record first seen at barrier `f` cannot influence barriers before `f`, because the
//! accept loop at barrier `b` only considers records with `first_barrier <= b`. Crossing
//! a barrier with no new record processes just that barrier. The result is the same
//! deterministic function as a full replay (the test build asserts this on every
//! incremental rebuild); only records older than the checkpoint window fall back to one.
//!
//! # The root discipline (the security claim d1 rests on)
//!
//! d1 §assumption 3: *the replica pins a root it derived itself, never a root from
//! a proof or a peer.* Here that is literal. An object proof is verified against
//! `Some(root)` where `root` is one this replica produced (§5.1, monotone — any
//! recent produced root is safe, held in a window of the last `K`). A scan's
//! callback roots are the replica's **own current-barrier** roots, rebuilt from
//! its own called set (§5.2, anti-monotone — the latest barrier only, no grace);
//! a scan naming a superseded barrier simply has no matching root and is rejected.
//! That is the structural O10 fix carried into the engine.
//!
//! # Scope (d3)
//!
//! Built here: the accept rules for every [`Record`] kind; the object-root window;
//! nullifier-first-wins; the barriers ([`Replica::advance_to`]) that fire the
//! **derived** triggers (poll-ban close and reputation settlement, §7) and re-pin the
//! callback root; the tallies and persona cache; view digests and claims (§5.5); and
//! append-only journal persistence. The messenger receive loop, rendering and late
//! join live in `personas-messenger`, and the heartbeat that drives the barriers in
//! its `Heartbeat`. `FoldScan` is off by default (§13).
//!
//! The *authorized* triggers are not authenticated here. An admin [`Record::Ban`] and
//! [`Record::RejoinApprove`] are accepted by the client only from a Signal group admin
//! (they travel under the admin's own account), and a [`Record::BadgeApprove`] is not
//! checked at all; see its docs. The signed authority keys of §7/§11 are not built.

pub mod record;
pub mod tally;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use ark_ff::PrimeField;
use ark_ff::ToConstraintField;
use ark_snark::SNARK;
use personas_core::{H, PreparedVk};
use zk_callbacks::crypto::enc::AECipherSigZK;
use zk_callbacks::generic::bulletin::CallbackBul;
use zk_callbacks::generic::object::Time;
use zk_callbacks::impls::centralized::crypto::FakeSigPrivkey;

use personas_core::circuits::{
    BADGE1_FLAG, BADGE2_FLAG, BADGE3_FLAG, BAN_FLAG, BadgesArgs, NUM_SCANS_PER_FOLD, PseudonymArgs,
    PseudonymArgsRate, RATE_LIMITED_PERSONAS_PER_CONTEXT, arg_rep,
};
use personas_core::params::ServerKeys;
use personas_core::{Cr, F, Snark, VK};

use crate::merkle::callback::{DEFAULT_CB_MEMB_HEIGHT, DEFAULT_CB_NMEMB_HEIGHT};
use crate::merkle::obj::DEFAULT_OBJ_HEIGHT;
use crate::merkle::params::merkle_scan_pubdata;
use crate::merkle::{MerkleCallbackStore, MerkleObjStore};

use record::{Eh, Flavour, PollKind, Record};
use tally::{Derived, LogEntry, Outstanding, Poll, f_key};

/// The verifying keys a replica needs. A subset of [`ServerKeys`] — only the
/// verifying halves, and only Merkle mode.
///
/// The heights the keys were generated for are a type-level contract with the
/// [`Replica`]'s const generics, exactly as in d1: a key built for a height-32
/// object tree verifies only a proof made against one.
#[derive(Clone)]
pub struct ReplicaKeys {
    /// Standard (anonymous) post.
    pub standard: VK,
    /// Pseudonymous post.
    pub pseudo: VK,
    /// Rate-limited pseudonymous post.
    pub pseudo_rate: VK,
    /// Callback scan.
    pub scan: VK,
    /// The `pseudonym_pred` statement — a vote or a proof-carrying rating (§10).
    pub pseudonym_pred: VK,
    /// A badge request interaction. Already in every `ServerKeys` bundle.
    pub badge_request: VK,
    /// A join's freshness proof (`join_pred`).
    pub join: VK,
    /// A re-join's proof about the object given up (`not_banned_pred`).
    pub not_banned: VK,
}

/// [`ReplicaKeys`], each prepared once for verification ([`PreparedVk`]).
pub(crate) struct PreparedKeys {
    standard: PreparedVk,
    pseudo: PreparedVk,
    pseudo_rate: PreparedVk,
    scan: PreparedVk,
    pseudonym_pred: PreparedVk,
    badge_request: PreparedVk,
    join: PreparedVk,
    not_banned: PreparedVk,
}

impl PreparedKeys {
    fn new(keys: &ReplicaKeys) -> Self {
        Self {
            standard: PreparedVk::new(&keys.standard),
            pseudo: PreparedVk::new(&keys.pseudo),
            pseudo_rate: PreparedVk::new(&keys.pseudo_rate),
            scan: PreparedVk::new(&keys.scan),
            pseudonym_pred: PreparedVk::new(&keys.pseudonym_pred),
            badge_request: PreparedVk::new(&keys.badge_request),
            join: PreparedVk::new(&keys.join),
            not_banned: PreparedVk::new(&keys.not_banned),
        }
    }
}

impl ReplicaKeys {
    /// Take the verifying keys out of a full [`ServerKeys`] bundle (as produced by
    /// `merkle::params::generate_merkle_server_keys`).
    pub fn from_server_keys(keys: &ServerKeys) -> Self {
        Self {
            standard: keys.standard_verifying_key.clone(),
            pseudo: keys.standard_pseudo_verifying_key.clone(),
            pseudo_rate: keys.standard_pseudor_verifying_key.clone(),
            scan: keys.scan_verifying_key.clone(),
            pseudonym_pred: keys.pseudonym_pred_verifying_key.clone(),
            badge_request: keys.badge_request_verifying_key.clone(),
            join: keys.join_pred_verifying_key.clone(),
            not_banned: keys.not_banned_pred_verifying_key.clone(),
        }
    }
}

/// Replica parameters, all with the `SERVERLESS_PROTOCOL.md` §14 defaults.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// `K`: how far behind a prover's object root may lag before it is dropped
    /// rather than buffered. Safe at any size (monotone, §5.1); bounds memory.
    pub root_window: usize,
    /// `W`: how many barriers a post's ticket lives before forced settlement (§7).
    pub settlement_barriers: u64,
    /// How many barriers a poll accepts votes for before it closes (§8).
    pub poll_close_barriers: u64,
}

/// How long a post's ticket stays open to a ban.
pub const BAN_WINDOW_MS: u64 = 48 * 60 * 60 * 1000;
/// How long a poll takes ballots.
pub const POLL_OPEN_MS: u64 = 24 * 60 * 60 * 1000;
/// The barrier period a group gets unless its bundle says otherwise.
pub const DEFAULT_BARRIER_PERIOD_MS: u64 = 10_000;

impl Config {
    /// The deployed windows, in barriers of `period_ms`. Every member derives these from
    /// the period in the group's bundle, so they cannot disagree.
    pub fn for_period_ms(period_ms: u64) -> Self {
        let period = period_ms.max(1);
        Self {
            root_window: 256,
            settlement_barriers: BAN_WINDOW_MS.div_ceil(period),
            poll_close_barriers: POLL_OPEN_MS.div_ceil(period),
        }
    }

    /// Windows of a few barriers, for tests and benchmarks that cross them on purpose.
    pub fn fast() -> Self {
        Self {
            root_window: 256,
            settlement_barriers: 3,
            poll_close_barriers: 2,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::for_period_ms(DEFAULT_BARRIER_PERIOD_MS)
    }
}

/// What became of a record once the replica applied the accept rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Accepted and folded into the bulletin.
    Applied,
    /// Well-formed, but it names an object root this replica has not produced —
    /// the prover is ahead, or the record is orphaned. Retried on every rebuild;
    /// dropped once its root ages past the window (§5.1).
    Buffered,
    /// Rejected: the proof failed, the nullifier was already spent (a double-spend
    /// lost the §4 linearization), the scan named a superseded barrier (§5.2), or
    /// the record referenced something that does not exist.
    Rejected(&'static str),
}

/// A record the replica has seen, with the barrier it first arrived at.
struct Seen {
    bytes: Vec<u8>,
    record: Record,
    /// The `current_barrier` when this record was first ingested. Settlement and
    /// poll-close are measured from it (§7, §8).
    first_barrier: u64,
    /// The sender's view of the group when it sent the record, if it carried one
    /// ([`Replica::view_report`]).
    view: Option<record::ViewClaim>,
}

/// A serverless replica: the ordered log in, a convergent bulletin out.
pub struct Replica<
    const OH: usize = DEFAULT_OBJ_HEIGHT,
    const MH: usize = DEFAULT_CB_MEMB_HEIGHT,
    const NH: usize = DEFAULT_CB_NMEMB_HEIGHT,
> {
    /// The verifying keys, each prepared once for verification.
    prepared: PreparedKeys,
    config: Config,

    /// Every record seen, keyed and *ordered* by envelope hash — the §4 tiebreak
    /// is `BTreeMap`'s ascending-key iteration.
    seen: std::collections::BTreeMap<Eh, Seen>,
    /// Memoised Groth16 results: a proof's validity against the root it names is a
    /// fixed fact, computed once and reused across every rebuild.
    verify_cache: HashMap<Eh, bool>,

    /// The barrier the replica has reached; advanced by [`Replica::barrier`].
    current_barrier: u64,

    // --- Derived by rebuild (a pure function of the fields above) --------------
    /// The bulletin as it stands at the end of barrier `state_at` (== `current_barrier`
    /// after every rebuild): object tree, callback sets, produced roots, tallies, log
    /// and statuses.
    state: BuildState<OH, MH, NH>,
    state_at: u64,

    /// The rebuild's state at the end of each of the last [`CHECKPOINT_BARRIERS`]
    /// barriers BEFORE `state_at`, so a change replays from where it can first matter
    /// instead of from genesis (see the module docs). The end of `state_at` itself is
    /// `state`, kept once rather than copied.
    checkpoints: std::collections::BTreeMap<u64, BuildState<OH, MH, NH>>,

    /// TEST BUILDS ONLY: accept a join without checking its freshness proof, for the
    /// proof-free ordering tests that build joins without keys. Always false otherwise.
    trust_unproven_joins: bool,
    /// TEST BUILDS ONLY: store records carrying placeholder proofs, so a test can exercise
    /// buffering without generating keys.
    admit_unproven_for_tests: bool,

    /// Append-only journal of accepted record bytes; replayed on [`Replica::open`].
    journal: Option<PathBuf>,

    /// The latest barrier at which callbacks were invoked, and how long that took
    /// ([`SettleTimings`]). For benchmarks; nothing reads it otherwise.
    last_settle: Option<(u64, SettleTimings)>,
}

/// What a barrier's settlement cost: the callbacks invoked ("post callback" — encrypt the
/// argument and append it to the called set) and the epoch update that follows (re-pinning
/// the non-membership root over the grown called set).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SettleTimings {
    pub invoked: u32,
    pub invoke_us: u64,
    pub epoch_update_us: u64,
}

impl<const OH: usize, const MH: usize, const NH: usize> Replica<OH, MH, NH> {
    /// A fresh in-memory replica (no persistence).
    pub fn new(keys: ReplicaKeys, config: Config) -> Self {
        let genesis = BuildState::genesis(config.root_window);
        let mut r = Self {
            prepared: PreparedKeys::new(&keys),
            config,
            seen: std::collections::BTreeMap::new(),
            verify_cache: HashMap::new(),
            current_barrier: 0,
            state: genesis,
            state_at: 0,
            checkpoints: std::collections::BTreeMap::new(),
            trust_unproven_joins: false,
            admit_unproven_for_tests: false,
            journal: None,
            last_settle: None,
        };
        r.rebuild();
        r
    }

    /// A replica backed by an append-only journal at `path`, replaying any records
    /// already there.
    ///
    /// The journal is the "persisted incrementally" of the plan, and it is
    /// deliberately a *log of records*, not a serialised bulletin: `CentralStore`
    /// is not `CanonicalSerialize` (the a2/O1 finding) and neither is a live
    /// replica, but the records that produced it are exactly the bytes that arrived
    /// over the wire. Replaying them rebuilds identical state — which is the same
    /// determinism convergence already requires.
    pub fn open(
        path: impl Into<PathBuf>,
        keys: ReplicaKeys,
        config: Config,
    ) -> std::io::Result<Self> {
        let path = path.into();
        let existing = read_journal(&path)?;
        let mut r = Self::new(keys, config);
        r.journal = Some(path);
        for bytes in existing {
            // Records already in the journal were accepted once; ingest them without
            // re-journaling (the `journal` write is skipped for replayed bytes). The
            // journal stores only bytes, not the barrier a record first arrived at, so
            // replay re-assigns `first_barrier = 0`; the barrier-faithful restore path is
            // the d4 snapshot ([`from_records`]), which carries the schedule.
            let at = r.current_barrier;
            let _ = r.ingest_inner(bytes, at, false, false);
        }
        Ok(r)
    }

    /// Rebuild a replica from a snapshot's records and barrier schedule (d4 late
    /// join, `SERVERLESS_PROTOCOL.md` §12).
    ///
    /// A [`Snapshot`](../../messenger/snapshot) is faithful only if the joiner
    /// reproduces not just the record *set* but each record's **first-seen barrier**
    /// and the current barrier — the engine's state is a function of all three (§5.2,
    /// the determinism caveat). This takes exactly that: `(first_barrier, bytes)` per
    /// record, plus the barrier the snapshot was taken at. Malformed records in the
    /// snapshot are skipped (they could not have been accepted anyway).
    ///
    /// The result is derived by the same `rebuild` as a live replica, so an adopted
    /// snapshot computes byte-identical roots to the replica it came from — which is
    /// exactly the self-revealing property §12 relies on: a tampered snapshot yields
    /// roots the group does not share, and the joiner's own proofs are then rejected.
    pub fn from_records(
        keys: ReplicaKeys,
        config: Config,
        records: Vec<(u64, Vec<u8>)>,
        current_barrier: u64,
    ) -> Self {
        let mut r = Self::new(keys, config);
        r.current_barrier = current_barrier;
        for (first_barrier, bytes) in records {
            if let Ok((record, eh, view)) = record::decode_with_view(&bytes) {
                r.seen.entry(eh).or_insert(Seen {
                    bytes,
                    record,
                    first_barrier,
                    view,
                });
            }
        }
        r.rebuild();
        r
    }

    /// Every seen record as `(first_barrier, bytes)`, in canonical (ascending-`eh`)
    /// order — the material a [`Snapshot`](../../messenger/snapshot) hands a late
    /// joiner. Ascending order comes from the `BTreeMap` key iteration, so the list
    /// is deterministic and a digest over it is stable across replicas.
    pub fn seen_with_barriers(&self) -> Vec<(u64, Vec<u8>)> {
        self.seen
            .values()
            .map(|s| (s.first_barrier, s.bytes.clone()))
            .collect()
    }

    /// Every seen record for a LATE JOINER, as `(first_barrier, eh, bytes)` with the
    /// private text removed ([`record::strip_private_text`]). A record's identity does
    /// not cover the text, so a stripped record keeps its `eh`.
    pub fn catch_up_records(&self) -> Vec<(u64, Eh, Vec<u8>)> {
        self.seen
            .iter()
            .filter_map(|(eh, s)| {
                let bytes = record::strip_private_text(&s.bytes).ok()?;
                Some((s.first_barrier, *eh, bytes))
            })
            .collect()
    }

    /// Add many records at once with ONE rebuild: ingesting a whole history one record at
    /// a time would replay it once per record. Already-seen records are skipped; ones
    /// that are malformed, do not hash to the `eh` given or fail their proof are ignored.
    /// Returns how many were new.
    pub fn import_records(&mut self, items: Vec<(u64, Eh, Vec<u8>)>) -> usize {
        let built = self.current_barrier;
        let mut from: Option<u64> = None;
        let mut added = 0;
        for (first_barrier, eh, bytes) in items {
            if self.seen.contains_key(&eh) {
                continue;
            }
            let Ok((record, identity, view)) = record::decode_with_view(&bytes) else {
                continue;
            };
            // A record is what it hashes to and what its proof shows, whoever supplied
            // it. A poll's identity covers the text this copy leaves out, so a poll is the
            // exception, and a copy can still leave records out: those rest on the sender.
            let is_poll = matches!(record, Record::PollOpen { .. });
            if (!is_poll && identity != eh) || self.admissible_without_text(&record, eh).is_err() {
                continue;
            }
            self.seen.insert(
                eh,
                Seen {
                    bytes,
                    record,
                    first_barrier,
                    view,
                },
            );
            self.current_barrier = self.current_barrier.max(first_barrier);
            from = Some(from.map_or(first_barrier, |f| f.min(first_barrier)));
            added += 1;
        }
        if let Some(from) = from {
            self.rebuild_from(from.min(built + 1));
        }
        added
    }

    /// The stored bytes of a seen record (stripped, for one imported by
    /// [`import_records`](Self::import_records)).
    pub fn seen_bytes(&self, eh: &Eh) -> Option<&[u8]> {
        self.seen.get(eh).map(|s| s.bytes.as_slice())
    }

    /// Ingest one encoded record, assigning it the replica's current barrier as its
    /// first-seen barrier. Returns its [`Status`] after re-deriving state.
    ///
    /// Idempotent by envelope hash: a record delivered twice (the messenger may)
    /// is ingested once. A malformed or wrong-version record is refused before it
    /// reaches the mempool.
    ///
    /// This uses the *local* barrier the replica has reached, which is
    /// delivery-timing-dependent. The convergent path is [`ingest_at`](Self::ingest_at),
    /// which the messenger drives with a barrier bucketed from the record's
    /// **service-assigned** timestamp so every replica agrees on it (§4/§14, d5).
    pub fn ingest(&mut self, bytes: Vec<u8>) -> Result<Status, record::CodecError> {
        let at = self.current_barrier;
        self.ingest_inner(bytes, at, true, false)
    }

    /// Ingest a record whose first-seen barrier is supplied by the caller — the d5
    /// cadence path.
    ///
    /// The messenger computes `first_barrier` by bucketing the record's
    /// service-assigned receive timestamp against the shared heartbeat schedule
    /// (`SERVERLESS_PROTOCOL.md` §14). Because that stamp is identical on every
    /// replica, the record→barrier map is identical everywhere, so two replicas that
    /// have ingested the same records **and reached the same barrier** compute
    /// byte-identical roots — the exact-convergence property (§5.2's determinism
    /// caveat closed). A record serviced in a bucket later than the replica has
    /// reached pulls `current_barrier` forward to it: the provider's stamp is proof
    /// that time advanced at least that far.
    ///
    /// This path is **authoritative**: if the record was already present under a
    /// *provisional* barrier (a sender's own optimistic self-fold via [`ingest`], which
    /// cannot yet know the service timestamp), the service-stamped barrier supplied here
    /// replaces it. That is how a sender's own record converges to the same barrier every
    /// peer buckets it into — the "emit-then-ingest-own-echo" finalisation (d4/§5.4).
    pub fn ingest_at(
        &mut self,
        bytes: Vec<u8>,
        first_barrier: u64,
    ) -> Result<Status, record::CodecError> {
        self.ingest_inner(bytes, first_barrier, true, true)
    }

    /// Ingest a record RELAYED by another member, at the barrier the relay says the
    /// group placed it at (§5.5). Used when the messenger seems to have withheld the
    /// record from us.
    ///
    /// Not authoritative. A record we already hold keeps its own barrier, so a relay
    /// cannot move a record that the service delivered to us. The caller must cap
    /// `first_barrier` at the relay message's own service-stamped barrier: a record
    /// cannot have been placed after it was relayed. The relayer could still claim an
    /// earlier barrier than the group used. That error shows up as a view mismatch,
    /// as any other split does. A record that is not [relayable](Record::relayable) is
    /// refused.
    pub fn ingest_relayed(
        &mut self,
        bytes: Vec<u8>,
        first_barrier: u64,
    ) -> Result<Status, record::CodecError> {
        if !record::decode(&bytes)?.0.relayable() {
            return Ok(Status::Rejected(
                "a relay cannot carry a sender-checked record",
            ));
        }
        self.ingest_inner(bytes, first_barrier, true, false)
    }

    fn ingest_inner(
        &mut self,
        bytes: Vec<u8>,
        first_barrier: u64,
        journal: bool,
        authoritative: bool,
    ) -> Result<Status, record::CodecError> {
        let (rec, eh, view) = record::decode_with_view(&bytes)?;
        if let Some(prev) = self.seen.get(&eh) {
            // Already seen. An authoritative (service-stamped) re-arrival reconciles a
            // provisional barrier assigned by an optimistic self-fold; anything else is
            // an ordinary duplicate and is ignored.
            if authoritative && prev.first_barrier != first_barrier {
                let from = prev.first_barrier.min(first_barrier);
                self.seen.get_mut(&eh).expect("just found").first_barrier = first_barrier;
                let built = self.current_barrier;
                self.current_barrier = self.current_barrier.max(first_barrier);
                self.rebuild_from(from.min(built + 1));
            }
            return Ok(self
                .state
                .statuses
                .get(&eh)
                .cloned()
                .unwrap_or(Status::Buffered));
        }
        // Records replayed from the journal were admitted when they first arrived.
        if journal && let Err(reason) = self.admissible(&rec, eh) {
            return Ok(Status::Rejected(reason));
        }
        if journal && let Some(path) = &self.journal {
            append_journal(path, &bytes);
        }
        // A record whose bucket is ahead of where we've reached is itself evidence the
        // schedule advanced that far (the provider serviced it then), so cross to it.
        let built = self.current_barrier;
        self.current_barrier = self.current_barrier.max(first_barrier);
        self.seen.insert(
            eh,
            Seen {
                bytes,
                record: rec,
                first_barrier,
                view,
            },
        );
        // The common case — a record for the barrier we stand at that sorts after every
        // record already applied in it — continues that barrier's pass in place; any
        // other arrival replays from the first barrier it can affect.
        let in_order = self.state.pass_max.is_none_or(|max| eh > max);
        if first_barrier == built && self.state_at == built && in_order {
            self.continue_pass(built);
        } else {
            self.rebuild_from(first_barrier.min(built + 1));
        }
        Ok(self
            .state
            .statuses
            .get(&eh)
            .cloned()
            .unwrap_or(Status::Buffered))
    }

    /// Cross exactly one barrier: the settlement heartbeat, a ban, or an authority
    /// invocation (§5.2, §7). Equivalent to [`advance_to`](Self::advance_to) of the
    /// next barrier. Kept for callers that drive barriers by hand (the d4 tests and
    /// the CLI demo).
    pub fn barrier(&mut self) {
        self.advance_to(self.current_barrier + 1);
    }

    /// Advance the replica to `barrier`, settling every ticket that has since come
    /// due, closing every ban poll whose window has elapsed, and re-pinning the
    /// callback root (§5.2, §7). A no-op if already at or past `barrier`.
    ///
    /// This is the d5 heartbeat's settle trigger: the messenger calls it with the
    /// barrier its shared clock says "now" has reached, so tickets settle on cadence
    /// even when no new records arrive. `current_barrier` is monotone, so a lagging
    /// local clock only settles *late* (bounded by `W`, self-healing), never at a
    /// barrier a peer disagrees with — the divergence is transient (§5.2(a)).
    pub fn advance_to(&mut self, barrier: u64) {
        if barrier <= self.current_barrier {
            return;
        }
        let built = self.current_barrier;
        self.current_barrier = barrier;
        // Nothing before `built` changed: carry on from the state already reached.
        self.rebuild_from(built + 1);
    }

    // --- Views (§5.5) -----------------------------------------------------------

    /// The digest of this replica's view of the group up to and including `barrier`.
    ///
    /// A hash chain over the barriers that hold any record, each link committing to
    /// the barrier number and the envelope hashes of every record placed at it (applied,
    /// buffered or rejected) in ascending order. The bulletin is a deterministic
    /// function of exactly these inputs, so equal digests mean equal state. It is
    /// a chain so that, once two members' views of a barrier differ, every later digest
    /// differs too: the messenger cannot split a group and later merge it again without
    /// someone noticing.
    pub fn view_digest(&self, barrier: u64) -> [u8; 32] {
        self.view_digests()
            .range(..=barrier)
            .next_back()
            .map_or_else(view_genesis, |(_, d)| *d)
    }

    /// The claim this replica's member attaches to a record it sends now: the digest
    /// at [`VIEW_CLAIM_LAG`] barriers back, by which point every record placed at that
    /// barrier should have been delivered. `None` until the group is that old.
    pub fn view_claim(&self) -> Option<record::ViewClaim> {
        let barrier = self.current_barrier.checked_sub(VIEW_CLAIM_LAG)?;
        Some(record::ViewClaim {
            barrier,
            digest: self.view_digest(barrier),
        })
    }

    /// Compare the view claims carried by recent records with this replica's own view.
    ///
    /// Only claims about barriers at least [`VIEW_CLAIM_LAG`] behind this replica are
    /// checked (before that, the difference may only be our own delivery lag), and only
    /// those within the last [`VIEW_WINDOW`] barriers (an old mismatch from a member who
    /// was briefly behind, and has since caught up, ages out). A split that persists keeps
    /// producing fresh mismatches as long as the other side keeps sending.
    pub fn view_report(&self) -> ViewReport {
        let digests = self.view_digests();
        let at = |b: u64| {
            digests
                .range(..=b)
                .next_back()
                .map_or_else(view_genesis, |(_, d)| *d)
        };
        let oldest = self.current_barrier.saturating_sub(VIEW_WINDOW);
        let mut report = ViewReport::default();
        for (eh, s) in &self.seen {
            let Some(claim) = s.view else { continue };
            if claim.barrier < oldest {
                continue;
            }
            if claim.barrier + VIEW_CLAIM_LAG > self.current_barrier {
                report.pending += 1;
            } else if claim.digest == at(claim.barrier) {
                report.agreeing += 1;
            } else {
                report.mismatches.push(ViewMismatch {
                    barrier: claim.barrier,
                    record: *eh,
                });
            }
        }
        report.mismatches.sort_by_key(|m| (m.barrier, m.record));
        report
    }

    /// Every [relayable](Record::relayable) seen record placed at a barrier in
    /// `from..=to`, as `(first_barrier, bytes)`: what a member relays when it sees a view
    /// mismatch (§5.5).
    pub fn relayable_between(&self, from: u64, to: u64) -> Vec<(u64, Vec<u8>)> {
        self.seen
            .values()
            .filter(|s| (from..=to).contains(&s.first_barrier) && s.record.relayable())
            .map(|s| (s.first_barrier, s.bytes.clone()))
            .collect()
    }

    /// The view digest at the end of every barrier that holds a record.
    fn view_digests(&self) -> std::collections::BTreeMap<u64, [u8; 32]> {
        let mut by_barrier: std::collections::BTreeMap<u64, Vec<Eh>> =
            std::collections::BTreeMap::new();
        // `seen` iterates in ascending eh, so each barrier's list comes out sorted.
        for (eh, s) in &self.seen {
            by_barrier.entry(s.first_barrier).or_default().push(*eh);
        }
        let mut digest = view_genesis();
        by_barrier
            .into_iter()
            .map(|(b, ehs)| {
                use blake2::{Blake2s256, Digest};
                let mut h = Blake2s256::new();
                h.update(digest);
                h.update(b.to_le_bytes());
                h.update((ehs.len() as u64).to_le_bytes());
                for eh in &ehs {
                    h.update(eh.0);
                }
                digest = h.finalize().into();
                (b, digest)
            })
            .collect()
    }

    // --- Accessors --------------------------------------------------------------

    /// Whether `root` is one of the object roots this replica produced (within the
    /// last-`K` window) — the only roots a proof may be made against. Standalone proofs
    /// (badge possession, authorship) are not records and never pass the accept rule, so
    /// their verifier must ask this itself: a proof against a root the group never had is
    /// a proof about a tree the prover built, containing whatever object it liked.
    /// How many joins this replica has applied for `account`, and how many re-joins an
    /// admin has approved for it. A member may join while `joins < 1 + approved`.
    pub fn join_counts(&self, account: F) -> (u32, u32) {
        let key = f_key(account);
        (
            self.state.derived.joins.get(&key).copied().unwrap_or(0),
            self.state
                .derived
                .rejoin_allowance
                .get(&key)
                .copied()
                .unwrap_or(0),
        )
    }

    /// TEST BUILDS ONLY — see the field.
    #[cfg(test)]
    pub(crate) fn admit_unproven_for_tests(mut self) -> Self {
        self.admit_unproven_for_tests = true;
        self
    }

    /// TEST BUILDS ONLY — see the field.
    #[cfg(test)]
    pub(crate) fn trust_unproven_joins_for_tests(mut self) -> Self {
        self.trust_unproven_joins = true;
        self.rebuild();
        self
    }

    pub fn has_produced_root(&self, root: F) -> bool {
        self.state.produced.contains(&f_key(root))
    }

    /// The current object-tree root — the membership data a member proves against.
    pub fn obj_root(&self) -> F {
        self.state.obj.root()
    }

    /// The current callback membership root (called tickets).
    pub fn cb_memb_root(&self) -> F {
        self.state.cbs.memb_root()
    }

    /// The current callback nonmembership root (the pinned barrier, §5.2).
    pub fn cb_nmemb_root(&self) -> F {
        self.state.cbs.nmemb_root()
    }

    /// Read-only view of the object store, for a **co-located** member to build a
    /// membership proof against the replica's own tree (the d4 send side).
    ///
    /// This is a read of state the replica derived itself, not a root trusted from
    /// a peer — the member proves membership of *its* object against the current
    /// root, and the resulting record is then re-verified on ingest like any other.
    pub fn obj_store(&self) -> &MerkleObjStore<F, OH> {
        &self.state.obj
    }

    /// The object tree a member proves against: the end of the newest barrier that closed
    /// at least a full barrier ago ([`SETTLE_LAG`]). `None` until the group is that old.
    ///
    /// Every member who received the group's records holds this same tree, so a proof
    /// names a root that says nothing about what its prover has seen lately, and by the
    /// time a root is used the records stamped into its barrier have been delivered.
    pub fn proving_store(&self) -> Option<&MerkleObjStore<F, OH>> {
        self.proving_store_at(SETTLE_LAG)
    }

    /// [`proving_store`](Self::proving_store), `lag` barriers back. A messenger with a clock
    /// can use a lag of 1 once enough of the current barrier has passed.
    pub fn proving_store_at(&self, lag: u64) -> Option<&MerkleObjStore<F, OH>> {
        let barrier = self.current_barrier.checked_sub(lag)?;
        self.checkpoints
            .range(..=barrier)
            .next_back()
            .map(|(_, st)| &st.obj)
    }

    /// Whether a record is lost for good: it was refused, or it still waits on a root the
    /// group has not produced even though that root's barrier has settled. Its sender can
    /// take back the object it spent, because no replica will ever apply it.
    pub fn is_lost(&self, eh: &Eh) -> bool {
        let Some(seen) = self.seen.get(eh) else {
            return true;
        };
        match self.state.statuses.get(eh) {
            Some(Status::Applied) => false,
            Some(Status::Rejected(reason)) => *reason != NULLIFIER_SPENT,
            _ => seen.first_barrier + SETTLE_LAG < self.current_barrier,
        }
    }

    /// The context a pseudonymous post was made in; `None` for anything else, or for a
    /// context too large for a `u64`, which no topic has. Bound by the post's proof, which
    /// is what lets a client check the topic name the post displays.
    pub fn post_context(&self, eh: &Eh) -> Option<u64> {
        let Record::Post { flavour, extra, .. } = &self.seen.get(eh)?.record else {
            return None;
        };
        if *flavour == Flavour::Anon {
            return None;
        }
        let key = f_key(*extra.0.first()?);
        let (low, high) = key.split_at(8);
        high.iter()
            .all(|b| *b == 0)
            .then(|| u64::from_le_bytes(low.try_into().expect("eight bytes")))
    }

    /// How many records from other members name a root this replica never produced,
    /// though its barrier has settled. Honest members all produce the same roots, so any
    /// such record means someone was shown a different set of records (§5.5).
    pub fn foreign_roots(&self) -> usize {
        self.seen
            .iter()
            .filter(|(eh, s)| {
                s.first_barrier + SETTLE_LAG < self.current_barrier
                    && matches!(self.state.statuses.get(*eh), Some(Status::Buffered))
                    && !is_applicable(&s.record, &self.state.produced, &self.state.derived)
                    && record_root_of(&s.record).is_some_and(|root| {
                        !self.state.produced.contains(&f_key(root))
                    })
            })
            .count()
    }

    /// Read-only view of the callback store, for a co-located member to build a
    /// scan against the replica's **current-barrier** called set (§5.2). A scan is
    /// only ever valid against the latest barrier, so a member must read the live
    /// store here rather than reconstruct a stale one.
    pub fn callback_store(&self) -> &MerkleCallbackStore<F, MH, NH> {
        &self.state.cbs
    }

    /// The barrier the replica has reached.
    pub fn current_barrier(&self) -> u64 {
        self.current_barrier
    }

    /// The status the accept rule assigned a record, by envelope hash.
    /// The barrier a seen record is placed at (its `first_barrier`), or `None` if this
    /// replica has not seen it. What a persistent journal must record alongside the
    /// bytes to restore the replica faithfully (see [`from_records`](Self::from_records)).
    pub fn first_barrier(&self, eh: &Eh) -> Option<u64> {
        self.seen.get(eh).map(|s| s.first_barrier)
    }

    /// The latest barrier at which callbacks were invoked, with what it cost.
    pub fn last_settle_timings(&self) -> Option<(u64, SettleTimings)> {
        self.last_settle
    }

    /// BENCHMARKS: check a record's PROOF only — the same Groth16 check, with the same
    /// public inputs, that applying it makes — without ordering, buffering, caching or
    /// touching any state. `None` for a record that carries no proof (polls, approvals,
    /// bans) or that does not decode. A scan is checked against this replica's current
    /// callback set, as applying it would be.
    pub fn verify_record_proof(&self, bytes: &[u8]) -> Option<bool> {
        let (rec, eh) = record::decode(bytes).ok()?;
        self.record_proof_holds(&rec, eh)
    }

    fn record_proof_holds(&self, rec: &Record, eh: Eh) -> Option<bool> {
        let mut cache = HashMap::new();
        let ok = match rec {
            Record::Join {
                object,
                account,
                pk,
                proof,
                ..
            } => memo_statement(
                &mut cache,
                eh,
                &self.prepared.join,
                &[object.0, account.0, pk.0],
                &proof.0,
            ),
            Record::Post {
                flavour,
                exec,
                extra,
                payload,
                obj_root,
                ..
            } => {
                let exec = &exec.0;
                match flavour {
                    Flavour::Anon => memo_interaction::<OH, _, 1>(
                        &mut cache,
                        eh,
                        &self.prepared.standard,
                        exec.new_object,
                        exec.old_nullifier,
                        payload.0,
                        exec.cb_com_list,
                        &exec.proof,
                        obj_root.0,
                    ),
                    Flavour::Pseudo => memo_interaction::<OH, _, 1>(
                        &mut cache,
                        eh,
                        &self.prepared.pseudo,
                        exec.new_object,
                        exec.old_nullifier,
                        PseudonymArgs {
                            context: *extra.0.first()?,
                            claimed: *extra.0.get(1)?,
                            payload: payload.0,
                        },
                        exec.cb_com_list,
                        &exec.proof,
                        obj_root.0,
                    ),
                    Flavour::PseudoRate => memo_interaction::<OH, _, 1>(
                        &mut cache,
                        eh,
                        &self.prepared.pseudo_rate,
                        exec.new_object,
                        exec.old_nullifier,
                        PseudonymArgsRate {
                            context: *extra.0.first()?,
                            claimed: *extra.0.get(1)?,
                            i: *extra.0.get(2)?,
                            payload: payload.0,
                        },
                        exec.cb_com_list,
                        &exec.proof,
                        obj_root.0,
                    ),
                }
            }
            Record::BadgeRequest {
                exec,
                slot,
                obj_root,
            } => {
                let exec = &exec.0;
                memo_interaction::<OH, _, 1>(
                    &mut cache,
                    eh,
                    &self.prepared.badge_request,
                    exec.new_object,
                    exec.old_nullifier,
                    BadgesArgs {
                        i: F::from(u64::from(*slot)),
                        claimed: F::from(0),
                    },
                    exec.cb_com_list,
                    &exec.proof,
                    obj_root.0,
                )
            }
            Record::Scan { exec, obj_root, .. } => {
                let exec = &exec.0;
                let ps = merkle_scan_pubdata::<MH, NH, NUM_SCANS_PER_FOLD>(
                    &self.state.cbs,
                    Time::from(0),
                );
                memo_interaction::<OH, _, 0>(
                    &mut cache,
                    eh,
                    &self.prepared.scan,
                    exec.new_object,
                    exec.old_nullifier,
                    ps,
                    exec.cb_com_list,
                    &exec.proof,
                    obj_root.0,
                )
            }
            Record::Rate {
                target,
                delta,
                proof,
                claimed,
                obj_root,
            } => memo_predicate(
                &mut cache,
                eh,
                &self.prepared.pseudonym_pred,
                target.context(),
                claimed.0,
                record::rating_payload(*target, *delta),
                obj_root.0,
                &proof.0,
            ),
            Record::Vote {
                poll,
                option,
                proof,
                claimed,
                obj_root,
            } => memo_predicate(
                &mut cache,
                eh,
                &self.prepared.pseudonym_pred,
                poll.context(),
                claimed.0,
                record::ballot_payload(*poll, *option),
                obj_root.0,
                &proof.0,
            ),
            Record::RejoinApprove {
                account,
                spent: Some(spent),
            } => memo_statement(
                &mut cache,
                eh,
                &self.prepared.not_banned,
                &[account.0, spent.nul.0, spent.root.0],
                &spent.proof.0,
            ),
            Record::PollOpen { .. }
            | Record::BadgeApprove { .. }
            | Record::RejoinApprove { .. }
            | Record::Ban { .. } => return None,
        };
        Some(ok)
    }

    /// Whether a NEWLY arrived record may be stored at all.
    ///
    /// An identity leaves out proof bytes and other relayed fields, so a tampered copy has
    /// the same identity as the real record. It must be refused here, unstored, or its
    /// arrival first would make the real record look like a duplicate of it.
    fn admissible(&mut self, rec: &Record, eh: Eh) -> Result<(), &'static str> {
        if let Record::Post { body, payload, .. } = rec
            && !self.admit_unproven_for_tests
            && payload.0 != record::post_payload(body)
        {
            return Err("post text does not match its proof");
        }
        self.admissible_without_text(rec, eh)
    }

    /// [`admissible`](Self::admissible) for a late joiner's copy, whose posts arrive with
    /// their text removed: everything the proof covers but the text itself.
    fn admissible_without_text(&mut self, rec: &Record, eh: Eh) -> Result<(), &'static str> {
        if self.admit_unproven_for_tests {
            return Ok(());
        }
        match rec {
            // Checked against the callback set it names, when it is applied. Its identity
            // includes its proof, so a bad copy cannot block a good one.
            Record::Scan { .. } => return Ok(()),
            Record::Join { .. } if self.trust_unproven_joins => return Ok(()),
            Record::Post {
                flavour,
                exec,
                extra,
                ..
            } => {
                let expected = match flavour {
                    Flavour::Anon => 0,
                    Flavour::Pseudo => 2,
                    Flavour::PseudoRate => 3,
                };
                if extra.0.len() != expected {
                    return Err("post has the wrong public arguments");
                }
                if !ticket_is_committed(&exec.0) {
                    return Err("post ticket does not match its proof");
                }
            }
            Record::BadgeRequest { exec, .. } if !ticket_is_committed(&exec.0) => {
                return Err("badge request ticket does not match its proof");
            }
            _ => {}
        }
        match self.record_proof_holds(rec, eh) {
            Some(false) => Err("proof failed"),
            Some(true) => {
                self.verify_cache.insert(eh, true);
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub fn status(&self, eh: &Eh) -> Option<Status> {
        self.state.statuses.get(eh).cloned()
    }

    /// The raw encoded bytes of a seen record — what a late joiner's snapshot or a
    /// re-broadcast (d4) hands back out, verbatim, so its `eh` is preserved.
    pub fn record_bytes(&self, eh: &Eh) -> Option<&[u8]> {
        self.seen.get(eh).map(|s| s.bytes.as_slice())
    }

    /// The rendered log — accepted records in canonical order, for a client to
    /// display (d4 does the actual rendering).
    pub fn log(&self) -> &[LogEntry] {
        &self.state.derived.log
    }

    /// An open or recently-closed poll, by its `PollOpen` envelope hash.
    pub fn poll(&self, eh: &Eh) -> Option<&Poll> {
        self.state.derived.polls.get(eh)
    }

    /// Read access to the derived tallies (polls, outstanding tickets, personas).
    pub fn derived(&self) -> &Derived {
        &self.state.derived
    }

    // --- The rebuild (the accept rule) -----------------------------------------

    /// Re-derive the entire bulletin from the seen record set and the current
    /// barrier. Deterministic: the same inputs yield byte-identical trees.
    fn rebuild(&mut self) {
        self.rebuild_from(0);
    }

    /// Re-derive the bulletin, replaying from the start of barrier `from`: resume from
    /// the checkpoint at the end of `from - 1` and run barriers `from..=current`.
    /// Callers pass the earliest barrier their change can affect. Falls back to a full
    /// replay when that checkpoint has aged out (or `from` is 0).
    fn rebuild_from(&mut self, from: u64) {
        self.rebuild_from_inner(from);

        // The incremental path must be indistinguishable from a full replay; the test
        // build checks that on every incremental rebuild, so every engine test (the
        // proof-carrying e2e ones included) exercises it.
        #[cfg(test)]
        if from > 0 {
            let incremental = self.fingerprint();
            self.rebuild_from_inner(0);
            assert_eq!(
                incremental,
                self.fingerprint(),
                "incremental rebuild from barrier {from} diverged from a full replay"
            );
        }
    }

    fn rebuild_from_inner(&mut self, from: u64) {
        // Resume from the end of `from - 1`: the current state itself when the change
        // starts right after it (crossing a barrier), else its checkpoint, else genesis.
        let (from, mut st) = match from.checked_sub(1) {
            Some(prev) if prev == self.state_at => {
                let genesis = BuildState::genesis(self.config.root_window);
                let st = std::mem::replace(&mut self.state, genesis);
                // Keep the end of `prev` for a later change that starts at `from`.
                self.checkpoints.insert(prev, st.clone());
                (from, st)
            }
            Some(prev) => match self.checkpoints.get(&prev) {
                Some(st) => (from, st.clone()),
                None => (0, BuildState::genesis(self.config.root_window)),
            },
            None => (0, BuildState::genesis(self.config.root_window)),
        };
        // Checkpoints at or after `from` describe a past that no longer holds.
        drop(self.checkpoints.split_off(&from));

        // The records each barrier makes eligible, and those already eligible but not
        // yet applied (buffered) when the replay starts.
        let mut arriving: std::collections::BTreeMap<u64, Vec<Eh>> =
            std::collections::BTreeMap::new();
        let mut pending: std::collections::BTreeSet<Eh> = std::collections::BTreeSet::new();
        for (eh, s) in &self.seen {
            if st.applied.contains(eh) {
                continue;
            }
            if s.first_barrier < from {
                pending.insert(*eh);
            } else {
                arriving.entry(s.first_barrier).or_default().push(*eh);
            }
        }

        for b in from..=self.current_barrier {
            // Barrier `b - 1` has closed, so its root joins the roots a proof may name.
            // This is the only place a root is produced: the root at the end of a barrier
            // depends on the set of records in it and not on the order they arrived, so
            // a record racing another in the same barrier cannot strand anything.
            if b > 0 {
                let window = self.config.root_window;
                record_root(&mut st.produced, &mut st.produced_order, st.obj.root(), window);
            }

            // (1) The barrier event fires *first* (§5.2): settle every ticket due or
            //     banned as of the records applied through the previous barrier, and
            //     re-pin the callback root. A scan that arrives at barrier `b` must
            //     therefore prove against the *post*-settlement callback set — which
            //     is exactly what makes a ban enforceable the moment a replica crosses
            //     its barrier. (At `b == 0` there is nothing yet to settle.)
            let settled = settle_barrier(b, &self.config, &mut st.cbs, &mut st.derived);
            if settled.invoked > 0 {
                self.last_settle = Some((b, settled));
            }

            // (2) Apply every record now available, smallest eh first (§4).
            st.pass_max = None;
            if let Some(new) = arriving.remove(&b) {
                pending.extend(new);
            }
            self.run_pass(b, &mut st, &mut pending);

            if b < self.current_barrier && b + CHECKPOINT_BARRIERS >= self.current_barrier {
                self.checkpoints.insert(b, st.clone());
            }
        }

        // Keep only the recent past: a record is bucketed by its service timestamp, so
        // it lands at (or within a barrier or two of) the current barrier. Older
        // arrivals take the full-replay fallback.
        let keep_from = self.current_barrier.saturating_sub(CHECKPOINT_BARRIERS - 1);
        self.checkpoints = self.checkpoints.split_off(&keep_from);

        // Anything never applied and never rejected is waiting on a root it has not
        // seen (a prover ahead, or an orphan) — buffered.
        for eh in self.seen.keys() {
            st.statuses.entry(*eh).or_insert(Status::Buffered);
        }

        self.state = st;
        self.state_at = self.current_barrier;
    }

    /// One barrier's accept loop: repeatedly apply the smallest-eh record in `pending`
    /// that is applicable, until none is. Applying one can make an earlier one
    /// applicable (it produces the root that one names), so the search restarts from the
    /// smallest each time — the §4 tiebreak, exactly as a scan of every seen record in
    /// ascending eh would give, but over only the records still waiting.
    fn run_pass(
        &mut self,
        b: u64,
        st: &mut BuildState<OH, MH, NH>,
        pending: &mut std::collections::BTreeSet<Eh>,
    ) {
        loop {
            let next = pending.iter().copied().find(|eh| {
                self.seen
                    .get(eh)
                    .is_some_and(|s| is_applicable(&s.record, &st.produced, &st.derived))
            });
            let Some(eh) = next else { break };
            pending.remove(&eh);
            st.applied.insert(eh);
            st.pass_max = Some(st.pass_max.map_or(eh, |m| m.max(eh)));
            let status = self.apply(
                eh,
                b,
                &mut st.obj,
                &st.cbs,
                &mut st.derived,
            );
            st.statuses.insert(eh, status);
        }
    }

    /// Take in a NEW record placed at the barrier the state already stands at, when it
    /// sorts after every record applied in that barrier's pass. Replaying the barrier
    /// would choose exactly the same records in the same order up to here (each was the
    /// smallest applicable when chosen, and this one is larger than all of them), then
    /// continue with the waiting records plus this one — which is what this does,
    /// without copying or replaying anything. Anything else takes `rebuild_from`.
    fn continue_pass(&mut self, b: u64) {
        let genesis = BuildState::genesis(self.config.root_window);
        let mut st = std::mem::replace(&mut self.state, genesis);
        let mut pending: std::collections::BTreeSet<Eh> = self
            .seen
            .iter()
            .filter(|(eh, s)| s.first_barrier <= b && !st.applied.contains(*eh))
            .map(|(eh, _)| *eh)
            .collect();
        self.run_pass(b, &mut st, &mut pending);
        for eh in pending {
            st.statuses.entry(eh).or_insert(Status::Buffered);
        }
        self.state = st;

        #[cfg(test)]
        {
            let incremental = self.fingerprint();
            self.rebuild_from_inner(0);
            assert_eq!(
                incremental,
                self.fingerprint(),
                "continuing barrier {b}'s pass diverged from a full replay"
            );
        }
    }

    /// Everything observable about the derived bulletin, for the incremental-rebuild
    /// self-check.
    #[cfg(test)]
    fn fingerprint(&self) -> String {
        let mut statuses: Vec<_> = self
            .state
            .statuses
            .iter()
            .map(|(eh, s)| (eh.0, s.clone()))
            .collect();
        statuses.sort_by_key(|(eh, _)| *eh);
        let log: Vec<_> = self
            .state
            .derived
            .log
            .iter()
            .map(|e| (e.eh.0, e.kind, e.author.clone(), e.body.clone(), e.flagged))
            .collect();
        let mut outstanding: Vec<_> = self
            .state
            .derived
            .outstanding
            .iter()
            .map(|(eh, o)| (eh.0, o.settled, o.banned, o.badge_slot, o.settle_barrier))
            .collect();
        outstanding.sort_by_key(|o| o.0);
        let mut polls: Vec<_> = self
            .state
            .derived
            .polls
            .iter()
            .map(|(eh, p)| (eh.0, p.closed, p.opened_barrier))
            .collect();
        polls.sort_by_key(|p| p.0);
        let mut produced: Vec<_> = self.state.produced.iter().copied().collect();
        produced.sort();
        let mut joins: Vec<_> = self
            .state
            .derived
            .joins
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        joins.sort();
        let mut allowance: Vec<_> = self
            .state
            .derived
            .rejoin_allowance
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        allowance.sort();
        format!(
            "{:?}|{:?}|{:?}|{statuses:?}|{log:?}|{outstanding:?}|{polls:?}|{produced:?}|{joins:?}|{allowance:?}|{:?}",
            self.state.obj.root(),
            self.state.cbs.memb_root(),
            self.state.cbs.nmemb_root(),
            self.state.produced_order,
        )
    }

    /// Apply one record against the state being rebuilt. Only ever called when
    /// [`is_applicable`] holds, so any named object root is already produced.
    #[allow(clippy::too_many_arguments)]
    fn apply(
        &mut self,
        eh: Eh,
        barrier: u64,
        obj: &mut MerkleObjStore<F, OH>,
        cbs: &MerkleCallbackStore<F, MH, NH>,
        derived: &mut Derived,
    ) -> Status {
        let w = self.config.settlement_barriers;
        // Borrow the record out of `seen` for the duration; `self.verify_cache` is a
        // disjoint field, so a free helper can memoise while we hold `&record`.
        let seen = &self.seen[&eh];
        match &seen.record {
            Record::Join {
                object,
                account,
                pk,
                proof,
                ..
            } => {
                // FRESH OBJECTS ONLY. Without this a join appended any commitment at all,
                // so a member could join with a badge, a reputation or a clean ban flag of
                // its own making. The proof binds `[object, account]`.
                if !self.trust_unproven_joins
                    && !memo_statement(
                        &mut self.verify_cache,
                        eh,
                        &self.prepared.join,
                        &[object.0, account.0, pk.0],
                        &proof.0,
                    )
                {
                    return Status::Rejected("join proof failed");
                }
                // ONE JOIN PER ACCOUNT, plus one per admin re-join approval. Joins are
                // attributable (the client refuses one whose `account` is not its
                // sender), so this is one membership per Signal account: no Sybil
                // memberships, and no fresh identity to escape a ban without an admin.
                let key = f_key(account.0);
                let used = derived.joins.get(&key).copied().unwrap_or(0);
                let allowed = 1 + derived.rejoin_allowance.get(&key).copied().unwrap_or(0);
                if used >= allowed {
                    return Status::Rejected("account already joined");
                }
                // ONE SECRET KEY PER ACCOUNT, and the same one for good. Two accounts on one
                // key would share pseudonyms, so a ban on one object would leave the other
                // posting as the same persona, and a re-join under a new key would give its
                // owner a second vote in every poll.
                let pk_key = f_key(pk.0);
                if derived.pk_account.get(&pk_key).is_some_and(|a| *a != key) {
                    return Status::Rejected("public key belongs to another account");
                }
                if derived.account_pk.get(&key).is_some_and(|p| *p != pk_key) {
                    return Status::Rejected("account joined with another public key");
                }
                derived.pk_account.insert(pk_key, key);
                derived.account_pk.insert(key, pk_key);
                derived.joins.insert(key, used + 1);
                // A join consumes no real nullifier. The record's `old_nul` is not proved, so
                // honouring it would let a joiner mark someone else's nullifier spent.
                obj.push(object.0, F::from(0), Vec::new());
                derived.log.push(LogEntry {
                    eh,
                    kind: "Join",
                    author: None,
                    body: hex::encode(key),
                    flagged: false,
                });
                Status::Applied
            }

            Record::Ban { target } => {
                // An admin's decision (checked by the client before ingest): the post's
                // ticket falls due at once and is invoked with BAN_FLAG at the next
                // barrier (`settle_barrier`), exactly as a passed ban poll would. A
                // settled pseudonymous post passes the ban on (`Derived::ban`).
                if let Err(reason) = derived.ban(*target) {
                    return Status::Rejected(reason);
                }
                derived.log.push(LogEntry {
                    eh,
                    kind: "Ban",
                    author: None,
                    body: String::new(),
                    flagged: false,
                });
                Status::Applied
            }

            Record::RejoinApprove { account, spent } => {
                // Admin-ness is checked by the client before ingest (the record is sent
                // under the admin's own account). Here it grants the allowance and retires
                // the object given up, so it cannot stay in use beside the new one.
                if let Some(spent) = spent {
                    if !memo_statement(
                        &mut self.verify_cache,
                        eh,
                        &self.prepared.not_banned,
                        &[account.0, spent.nul.0, spent.root.0],
                        &spent.proof.0,
                    ) {
                        return Status::Rejected("re-join proof failed");
                    }
                    if obj.has_seen_nul(&spent.nul.0) {
                        return Status::Rejected("re-join names an object already moved on from");
                    }
                    obj.spend(spent.nul.0);
                }
                let key = f_key(account.0);
                *derived.rejoin_allowance.entry(key).or_insert(0) += 1;
                derived.log.push(LogEntry {
                    eh,
                    kind: "RejoinApprove",
                    author: None,
                    body: hex::encode(key),
                    flagged: false,
                });
                Status::Applied
            }

            Record::Post {
                flavour,
                exec,
                extra,
                body,
                payload,
                obj_root,
            } => {
                let exec = &exec.0;
                let root = obj_root.0;
                if !ticket_is_committed(exec) {
                    return Status::Rejected("post ticket does not match its proof");
                }
                let ok = match flavour {
                    Flavour::Anon => memo_interaction::<OH, _, 1>(
                        &mut self.verify_cache,
                        eh,
                        &self.prepared.standard,
                        exec.new_object,
                        exec.old_nullifier,
                        payload.0,
                        exec.cb_com_list,
                        &exec.proof,
                        root,
                    ),
                    Flavour::Pseudo => {
                        let a = PseudonymArgs {
                            context: extra.0[0],
                            claimed: extra.0[1],
                            payload: payload.0,
                        };
                        memo_interaction::<OH, _, 1>(
                            &mut self.verify_cache,
                            eh,
                            &self.prepared.pseudo,
                            exec.new_object,
                            exec.old_nullifier,
                            a,
                            exec.cb_com_list,
                            &exec.proof,
                            root,
                        )
                    }
                    Flavour::PseudoRate => {
                        // THE RATE LIMIT, checked again here. The circuit proves `i` is
                        // one of 0..MAX_PSEUDO since protocol version 3; `i` is also a
                        // public input carried in the record, so the accept rule refuses
                        // an out-of-range index outright — a second line, and a clear
                        // reason, rather than a failed proof.
                        let limit = F::from(RATE_LIMITED_PERSONAS_PER_CONTEXT as u64);
                        if extra.0[2].into_bigint() >= limit.into_bigint() {
                            return Status::Rejected("persona index out of range");
                        }
                        let a = PseudonymArgsRate {
                            context: extra.0[0],
                            claimed: extra.0[1],
                            i: extra.0[2],
                            payload: payload.0,
                        };
                        memo_interaction::<OH, _, 1>(
                            &mut self.verify_cache,
                            eh,
                            &self.prepared.pseudo_rate,
                            exec.new_object,
                            exec.old_nullifier,
                            a,
                            exec.cb_com_list,
                            &exec.proof,
                            root,
                        )
                    }
                };
                if !ok {
                    return Status::Rejected("post proof failed");
                }
                if obj.has_seen_nul(&exec.old_nullifier) {
                    // First-reveal-wins: an earlier record already spent this
                    // object's nullifier, so this one is a double-spend (or a rewind
                    // to a stale state) and its successor is refused — it can never
                    // be built upon. Only the object's owner can even produce this,
                    // so a collision is self-inflicted.
                    return Status::Rejected(NULLIFIER_SPENT);
                }
                obj.push(
                    exec.new_object,
                    exec.old_nullifier,
                    exec.cb_com_list.to_vec(),
                );

                // File the callback ticket the poster committed to (§7).
                let callback = exec.cb_tik_list[0].0.clone();
                let claimed = match flavour {
                    Flavour::Anon => None,
                    Flavour::Pseudo | Flavour::PseudoRate => Some(tally::f_key(extra.0[1])),
                };
                let mut ticket = Outstanding::new(callback, Time::from(0), barrier + w, claimed);
                // A pseudonym a ban has reached: this post is flagged, and its ticket
                // carries the ban to the member's object.
                let flagged = claimed.is_some_and(|c| derived.banned_personas.contains(&c));
                ticket.banned = flagged;
                derived.outstanding.insert(eh, ticket);
                derived.open_tickets.insert(eh);

                // Render (minimally). A pseudonym gets a petname; an anon post none.
                let author = match flavour {
                    Flavour::Anon => None,
                    Flavour::Pseudo | Flavour::PseudoRate => Some(derived.petname(extra.0[1])),
                };
                derived.log.push(LogEntry {
                    eh,
                    kind: "Post",
                    author,
                    body: body.clone(),
                    flagged,
                });
                Status::Applied
            }

            Record::BadgeRequest {
                exec,
                slot,
                obj_root,
            } => {
                // Reject an out-of-range slot BEFORE anything else: the slot indexes
                // the badge selector in-circuit, and an unknown value could otherwise
                // be approved into a flag that means nothing.
                if *slot < 1 || *slot > 3 {
                    return Status::Rejected("badge slot out of range");
                }
                let exec = &exec.0;
                let root = obj_root.0;
                if !ticket_is_committed(exec) {
                    return Status::Rejected("badge request ticket does not match its proof");
                }
                // Same interaction shape as an anonymous post — one callback, no public
                // arguments — verified against the badge-request key.
                // PUBLIC ARGS MUST MATCH THE PROVER EXACTLY.
                //
                // `Member::badge_request` executes the interaction with
                // `BadgesArgs { i: slot, claimed: 0 }`, so the verifier has to rebuild
                // the same value from the record's own `slot`. Passing `F::from(0)`
                // here (as an anonymous post does) would verify a different statement
                // and fail every time — the same class of mistake as omitting the
                // membership root from an authorship proof.
                //
                // `claimed` is zero on a REQUEST because the badge's value is supplied
                // by the circuit when the approval flag is absorbed; the request only
                // names the slot.
                let pub_args = BadgesArgs {
                    i: F::from(*slot as u64),
                    claimed: F::from(0),
                };
                let ok = memo_interaction::<OH, _, 1>(
                    &mut self.verify_cache,
                    eh,
                    &self.prepared.badge_request,
                    exec.new_object,
                    exec.old_nullifier,
                    pub_args,
                    exec.cb_com_list,
                    &exec.proof,
                    root,
                );
                if !ok {
                    return Status::Rejected("badge request proof failed");
                }
                if obj.has_seen_nul(&exec.old_nullifier) {
                    return Status::Rejected(NULLIFIER_SPENT);
                }
                obj.push(
                    exec.new_object,
                    exec.old_nullifier,
                    exec.cb_com_list.to_vec(),
                );

                // The ticket an approval will invoke.
                let callback = exec.cb_tik_list[0].0.clone();
                derived
                    .outstanding
                    .insert(eh, Outstanding::new(callback, Time::from(0), barrier + w, None));
                derived.open_tickets.insert(eh);

                derived.log.push(LogEntry {
                    eh,
                    kind: "BadgeRequest",
                    author: None,
                    body: format!("requested badge slot {slot}"),
                    flagged: false,
                });
                Status::Applied
            }

            Record::BadgeApprove { target, slot } => {
                if *slot < 1 || *slot > 3 {
                    return Status::Rejected("badge slot out of range");
                }
                // Mark the REQUESTER's ticket. Everything after this is the existing
                // settlement path: at the close barrier it is invoked with the matching
                // BADGE flag, and the requester's next scan writes the badge in-circuit.
                match derived.outstanding.get_mut(target) {
                    Some(out) => {
                        if out.settled {
                            return Status::Rejected("badge request already settled");
                        }
                        out.badge_slot = Some(*slot);
                    }
                    None => return Status::Rejected("no such badge request"),
                }
                derived.log.push(LogEntry {
                    eh,
                    kind: "BadgeApprove",
                    author: None,
                    // Name the TARGET: without it the log cannot be paired with the
                    // request it approves, and an admin UI has no way to tell which
                    // requests are still pending.
                    body: format!("approved badge slot {slot} for {}", hex::encode(target.0)),
                    flagged: false,
                });
                Status::Applied
            }

            Record::Scan {
                exec,
                obj_root,
                cb_memb_root,
                cb_nmemb_root,
            } => {
                let exec = &exec.0;
                // §5.2: the scan must pin *this* replica's current-barrier callback
                // roots. If it named a superseded barrier, the roots differ and it is
                // stale — this is the whole O10 defense at the engine layer.
                if cb_memb_root.0 != cbs.memb_root() || cb_nmemb_root.0 != cbs.nmemb_root() {
                    return Status::Rejected("scan names a superseded barrier");
                }
                let ps = merkle_scan_pubdata::<MH, NH, NUM_SCANS_PER_FOLD>(cbs, Time::from(0));
                let ok = memo_interaction::<OH, _, 0>(
                    &mut self.verify_cache,
                    eh,
                    &self.prepared.scan,
                    exec.new_object,
                    exec.old_nullifier,
                    ps,
                    exec.cb_com_list,
                    &exec.proof,
                    obj_root.0,
                );
                if !ok {
                    return Status::Rejected("scan proof failed");
                }
                if obj.has_seen_nul(&exec.old_nullifier) {
                    return Status::Rejected(NULLIFIER_SPENT);
                }
                obj.push(exec.new_object, exec.old_nullifier, Vec::new());
                derived.log.push(LogEntry {
                    eh,
                    kind: "Scan",
                    author: None,
                    body: String::new(),
                    flagged: false,
                });
                Status::Applied
            }

            Record::PollOpen {
                question,
                options,
                kind,
                target,
            } => {
                derived.polls.insert(
                    eh,
                    Poll {
                        question: question.clone(),
                        options: options.clone(),
                        kind: *kind,
                        target: *target,
                        context: eh.context(),
                        opened_barrier: barrier,
                        ballots: HashMap::new(),
                        closed: false,
                    },
                );
                derived.open_polls.insert(eh);
                Status::Applied
            }

            Record::Vote {
                poll,
                option,
                proof,
                claimed,
                obj_root,
            } => {
                let context = poll.context();
                let ok = memo_predicate(
                    &mut self.verify_cache,
                    eh,
                    &self.prepared.pseudonym_pred,
                    context,
                    claimed.0,
                    record::ballot_payload(*poll, *option),
                    obj_root.0,
                    &proof.0,
                );
                if !ok {
                    return Status::Rejected("vote proof failed");
                }
                // Applicability guaranteed the poll exists.
                let open = derived.polls.get_mut(poll).expect("poll present by is_applicable");
                if open.closed {
                    return Status::Rejected("poll closed");
                }
                open.cast(claimed.0, *option);
                Status::Applied
            }

            Record::Rate {
                target,
                delta,
                proof,
                claimed,
                obj_root,
            } => {
                let context = target.context();
                let ok = memo_predicate(
                    &mut self.verify_cache,
                    eh,
                    &self.prepared.pseudonym_pred,
                    context,
                    claimed.0,
                    record::rating_payload(*target, *delta),
                    obj_root.0,
                    &proof.0,
                );
                if !ok {
                    return Status::Rejected("rating proof failed");
                }
                if delta.unsigned_abs() != 1 {
                    return Status::Rejected("a rating is +1 or -1");
                }
                derived.rate(*target, claimed.0, *delta as i64);
                Status::Applied
            }
        }
    }
}

/// How many recent barriers keep a rebuild checkpoint (see the module docs). At the
/// demo's 10 s heartbeat this is about ten minutes; a record bucketed further back than
/// that triggers one full replay.
const CHECKPOINT_BARRIERS: u64 = 64;

/// How many barriers behind the current one a proof's root is: the barrier before the
/// current one may still be receiving records stamped just before it closed, so the one
/// before that is the newest a member can rely on. A member's own new object can be proved
/// from once its barrier gets there, which is what paces its object-changing records.
pub const SETTLE_LAG: u64 = 2;

const NULLIFIER_SPENT: &str = "nullifier already spent";

/// How many barriers back a sender's [view claim](Replica::view_claim) is taken, and
/// how far behind a receiver a claim must be before it is checked. With a one-minute
/// heartbeat, a record has had at least a minute to reach everyone (§5.5, §14).
pub const VIEW_CLAIM_LAG: u64 = 2;

/// How many barriers of view claims [`Replica::view_report`] considers.
pub const VIEW_WINDOW: u64 = 10;

/// The digest of an empty view.
fn view_genesis() -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    Blake2s256::digest(b"personas-view-v1").into()
}

/// One record whose sender's view of a barrier differs from ours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewMismatch {
    pub barrier: u64,
    pub record: Eh,
}

/// The outcome of comparing recent view claims with our own view
/// ([`Replica::view_report`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewReport {
    /// Claims that match our view.
    pub agreeing: u32,
    /// Claims too recent to check yet.
    pub pending: u32,
    /// Claims that do not match our view, oldest barrier first.
    pub mismatches: Vec<ViewMismatch>,
}

impl ViewReport {
    /// Whether some member saw a different set of records than we did.
    pub fn diverged(&self) -> bool {
        !self.mismatches.is_empty()
    }
}

/// The rebuild's working state, as it stands at the end of a barrier.
#[derive(Clone)]
struct BuildState<const OH: usize, const MH: usize, const NH: usize> {
    obj: MerkleObjStore<F, OH>,
    cbs: MerkleCallbackStore<F, MH, NH>,
    derived: Derived,
    statuses: HashMap<Eh, Status>,
    produced: HashSet<[u8; 32]>,
    produced_order: VecDeque<[u8; 32]>,
    applied: HashSet<Eh>,
    /// The largest envelope hash applied in this barrier's pass so far: a record that
    /// sorts after it can be applied by continuing the pass instead of replaying it
    /// (see `ingest_inner`).
    pass_max: Option<Eh>,
}

impl<const OH: usize, const MH: usize, const NH: usize> BuildState<OH, MH, NH> {
    /// The empty bulletin, before barrier 0.
    fn genesis(root_window: usize) -> Self {
        let obj = MerkleObjStore::<F, OH>::new();
        let mut produced = HashSet::new();
        let mut produced_order = VecDeque::new();
        // The genesis (empty-tree) root is producible from the start.
        record_root(&mut produced, &mut produced_order, obj.root(), root_window);
        Self {
            obj,
            cbs: MerkleCallbackStore::new(),
            derived: Derived::default(),
            statuses: HashMap::new(),
            produced,
            produced_order,
            applied: HashSet::new(),
            pass_max: None,
        }
    }
}

/// Whether a record can be applied now: any object root it names has been
/// produced, and any record it references (a vote's poll) exists.
fn is_applicable(record: &Record, produced: &HashSet<[u8; 32]>, derived: &Derived) -> bool {
    let holds = |root: F| produced.contains(&f_key(root));
    match record {
        // No object root: applicable the moment its barrier arrives.
        Record::Join { .. } | Record::PollOpen { .. } => true,
        Record::RejoinApprove { spent, .. } => {
            spent.as_ref().is_none_or(|spent| holds(spent.root.0))
        }
        Record::Post { obj_root, .. } => holds(obj_root.0),
        Record::BadgeRequest { obj_root, .. } => holds(obj_root.0),
        // An approval pins no root: it carries no proof, only a reference to a ticket
        // the replica already holds.
        Record::BadgeApprove { target, .. } => derived.outstanding.contains_key(target),
        // Likewise a ban: it names a post whose ticket the replica holds.
        Record::Ban { target } => derived.outstanding.contains_key(target),
        Record::Rate { obj_root, .. } => holds(obj_root.0),
        Record::Scan { obj_root, .. } => holds(obj_root.0),
        Record::Vote { poll, obj_root, .. } => {
            holds(obj_root.0) && derived.polls.contains_key(poll)
        }
    }
}

/// The object root a record's proof names, if it has one.
fn record_root_of(record: &Record) -> Option<F> {
    match record {
        Record::Post { obj_root, .. }
        | Record::BadgeRequest { obj_root, .. }
        | Record::Rate { obj_root, .. }
        | Record::Scan { obj_root, .. }
        | Record::Vote { obj_root, .. } => Some(obj_root.0),
        _ => None,
    }
}

/// Add an object root to the produced-set, evicting the oldest once the window is
/// full (§5.1: a prover more than `K` roots behind is dropped, not buffered).
fn record_root(
    produced: &mut HashSet<[u8; 32]>,
    order: &mut VecDeque<[u8; 32]>,
    root: F,
    window: usize,
) {
    let key = f_key(root);
    if produced.insert(key) {
        order.push_back(key);
        while order.len() > window {
            if let Some(old) = order.pop_front() {
                produced.remove(&old);
            }
        }
    }
}

/// The barrier event (§7): close ban polls, then settle every due or banned
/// ticket into the callback tree, re-pinning the nonmembership root.
fn settle_barrier<const MH: usize, const NH: usize>(
    barrier: u64,
    config: &Config,
    cbs: &mut MerkleCallbackStore<F, MH, NH>,
    derived: &mut Derived,
) -> SettleTimings {
    let mut timings = SettleTimings::default();
    // (a) Close polls whose window has elapsed; a ban poll that passes bans its target.
    //     Ban strictly precedes reputation (§7 property 1), so this runs first.
    let mut banned_targets: Vec<Eh> = Vec::new();
    let mut closing: Vec<Eh> = Vec::new();
    for eh in &derived.open_polls {
        let poll = derived.polls.get_mut(eh).expect("an open poll exists");
        if barrier < poll.opened_barrier + config.poll_close_barriers {
            continue;
        }
        poll.closed = true;
        closing.push(*eh);
        if poll.kind == PollKind::Ban
            && poll.passes_ban()
            && let Some(target) = poll.target
        {
            banned_targets.push(target);
        }
    }
    for eh in closing {
        derived.open_polls.remove(&eh);
    }
    // `polls` is a HashMap, and a ban on a settled post picks a ticket: fix the order.
    banned_targets.sort();
    for target in banned_targets {
        // A target that does not exist or is out of reach simply goes unbanned.
        let _ = derived.ban(target);
    }

    // A ticket waits for a ban poll that was opened in time, so a poll cannot run out the
    // clock on its own target. Only such polls count: one opened during the wait could
    // otherwise be followed by another, holding a ticket and its reputation forever.
    let held: HashSet<Eh> = derived
        .open_polls
        .iter()
        .filter_map(|eh| derived.polls.get(eh))
        .filter(|p| p.kind == PollKind::Ban)
        .filter_map(|p| {
            let target = p.target?;
            let out = derived.outstanding.get(&target)?;
            (p.opened_barrier <= out.settle_barrier).then_some(target)
        })
        .collect();

    // (b) Settle every ticket now due (or banned), once. The OTP is additive and
    //     keyless (§6), so this call is a deterministic function of public data —
    //     every replica computes the identical called leaf.
    let mut due: Vec<Eh> = derived
        .open_tickets
        .iter()
        .map(|eh| (eh, derived.outstanding.get(eh).expect("an open ticket exists")))
        // A ban and a BADGE APPROVAL both fall due immediately; everything else waits
        // for its settlement window.
        //
        // The window exists so a reputation tally can ACCUMULATE: ratings arrive after
        // the post, so settling early would invoke the callback with a half-counted
        // score. Neither of these two has anything to accumulate. A ban is a decision
        // already taken, and so is a badge approval — the admin's record IS the
        // outcome, and waiting three barriers only delays handing it over.
        //
        // Deterministic across replicas, which is the requirement here: every replica
        // sees the same `BadgeApprove` record and sets the same `badge_slot`, so they
        // all compute the same due-set in the same barrier. (Being wrong about that
        // would fork the called-ticket tree, which is why it is worth stating.)
        //
        // Without this a badge took `settlement_barriers` × the barrier period to
        // arrive, during which the requester could scan repeatedly, correctly absorb
        // nothing, and reasonably conclude approval had silently failed.
        .filter(|(eh, o)| {
            o.banned
                || o.badge_slot.is_some()
                || (barrier >= o.settle_barrier && !held.contains(*eh))
        })
        .map(|(eh, _)| *eh)
        .collect();
    // The called-ticket tree is append-order-sensitive, and `outstanding` is a
    // HashMap (nondeterministic iteration), so the settlement order must be fixed
    // deterministically or replicas settling ≥2 tickets in one barrier would fork.
    // Ascending eh is the same tiebreak the log order uses (§4).
    due.sort();

    let mut any_called = false;
    for eh in due {
        let out = derived
            .outstanding
            .get(&eh)
            .expect("just collected")
            .clone();
        // ORDER MATTERS: a ticket is invoked once with one argument, so these are
        // mutually exclusive. Ban wins over a badge — a member being revoked should not
        // simultaneously be granted a credential.
        let arg = if out.banned {
            F::from(BAN_FLAG)
        } else if let Some(slot) = out.badge_slot {
            match slot {
                1 => F::from(BADGE1_FLAG),
                2 => F::from(BADGE2_FLAG),
                _ => F::from(BADGE3_FLAG),
            }
        } else {
            // Reputation is clamped so `r` cannot reach `BAN_FLAG` (§7 property, R8).
            arg_rep(out.clamped_rep())
        };
        let started = std::time::Instant::now();
        let called = invoke(cbs, &out, arg);
        timings.invoke_us += u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        if called {
            timings.invoked += 1;
            any_called = true;
            if let Some(o) = derived.outstanding.get_mut(&eh) {
                o.settled = true;
            }
            derived.open_tickets.remove(&eh);
        }
    }

    // Re-pin the nonmembership root over the (possibly grown) called set. The epoch
    // counter advances, but soundness rests on the range partition (d1 §3.3): a
    // grown called set yields a distinct partition and so a distinct root, which is
    // what makes a pre-ban scan stale.
    if any_called {
        let started = std::time::Instant::now();
        cbs.update_epoch();
        timings.epoch_update_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    }
    timings
}

/// Invoke a committed callback with `arg`, mirroring `ServiceProvider::call`: the
/// additive-OTP ciphertext of `arg` under the ticket's key, appended to the called
/// set. Returns whether the append happened (a ticket is called at most once).
fn invoke<const MH: usize, const NH: usize>(
    cbs: &mut MerkleCallbackStore<F, MH, NH>,
    out: &Outstanding,
    arg: F,
) -> bool {
    let enc_key = out.callback.cb_entry.enc_key.clone();
    let tik = out.callback.cb_entry.tik.clone();
    let (enc, sig) =
        <Cr as AECipherSigZK<F, F>>::encrypt_and_sign(arg, enc_key, FakeSigPrivkey::sk());
    <MerkleCallbackStore<F, MH, NH> as CallbackBul<F, F, Cr>>::verify_call_and_append(
        cbs,
        tik,
        enc,
        sig,
        out.filed_at,
    )
    .is_ok()
}

/// Whether the ticket a record publishes is the one its proof committed to.
///
/// The proof covers only the commitment, and the replica invokes the published ticket. A
/// client that published any other ticket would have posts no ban could ever reach.
fn ticket_is_committed(exec: &record::PostExec) -> bool {
    exec.cb_tik_list[0].0.commit::<H>() == exec.cb_com_list[0]
}

/// Verify an interaction proof against `obj_root`, memoised by `eh`.
///
/// The check runs on a *fresh* empty object store, so `has_never_received_nul`
/// is trivially true and `verify_interaction` reduces to the Groth16 check against
/// the named root supplied as `Some(obj_root)` — the pure, cacheable fact. The
/// real nullifier check and append happen at the call site, against the live tree.
#[allow(clippy::too_many_arguments)]
fn memo_interaction<const OH: usize, PubArgs, const NUMCBS: usize>(
    cache: &mut HashMap<Eh, bool>,
    eh: Eh,
    vk: &PreparedVk,
    new_object: F,
    old_nul: F,
    pub_args: PubArgs,
    cb_com_list: [F; NUMCBS],
    proof: &<Snark as SNARK<F>>::Proof,
    obj_root: F,
) -> bool
where
    PubArgs: ark_ff::ToConstraintField<F> + Clone,
{
    if let Some(&v) = cache.get(&eh) {
        return v;
    }
    // Exactly `UserBul::verify_interaction`'s public inputs, in its order: the new
    // object, the spent nullifier, the interaction's public arguments, the callback
    // commitments, then the membership root. (Its nullifier pre-check is trivially true
    // on a fresh store, so it is the Groth16 check alone — made here against the
    // prepared key; `verify_interaction` itself has no prepared-key entry point.)
    let mut inputs = vec![new_object, old_nul];
    let (Some(args), Some(cbs), Some(root)) = (
        pub_args.to_field_elements(),
        cb_com_list.to_field_elements(),
        obj_root.to_field_elements(),
    ) else {
        cache.insert(eh, false);
        return false;
    };
    inputs.extend(args);
    inputs.extend(cbs);
    inputs.extend(root);
    let v = vk.verify(&inputs, proof);
    cache.insert(eh, v);
    v
}

/// Verify a `pseudonym_pred` statement proof (a vote or a rating), memoised by
/// `eh`. The public inputs are `[context, claimed, payload, obj_root]` — `pub_args` first,
/// then the membership root, matching the statement circuit's allocation order —
/// and every one of them is supplied by the *replica* (`context` derived from the
/// referenced record, `obj_root` pinned to a produced root), so a forged context
/// or a stale root simply fails to verify.
/// Verify a standalone statement proof against explicit public inputs, memoised by `eh`.
fn memo_statement(
    cache: &mut HashMap<Eh, bool>,
    eh: Eh,
    vk: &PreparedVk,
    inputs: &[F],
    proof: &<Snark as SNARK<F>>::Proof,
) -> bool {
    if let Some(&v) = cache.get(&eh) {
        return v;
    }
    let v = vk.verify(inputs, proof);
    cache.insert(eh, v);
    v
}

fn memo_predicate(
    cache: &mut HashMap<Eh, bool>,
    eh: Eh,
    vk: &PreparedVk,
    context: F,
    claimed: F,
    payload: F,
    obj_root: F,
    proof: &<Snark as SNARK<F>>::Proof,
) -> bool {
    if let Some(&v) = cache.get(&eh) {
        return v;
    }
    let inputs = vec![context, claimed, payload, obj_root];
    let v = vk.verify(&inputs, proof);
    cache.insert(eh, v);
    v
}

// ---------------------------------------------------------------------------------------
// Journal persistence
// ---------------------------------------------------------------------------------------

/// Read a length-prefixed record journal, tolerating a truncated tail (a crash
/// mid-append loses at most the last record, never the whole log).
fn read_journal(path: &std::path::Path) -> std::io::Result<Vec<Vec<u8>>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let len = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        i += 4;
        if i + len > bytes.len() {
            tracing::warn!("truncated record journal tail dropped");
            break;
        }
        out.push(bytes[i..i + len].to_vec());
        i += len;
    }
    Ok(out)
}

/// Append one record to the journal, length-prefixed. Best-effort: a failed append
/// is logged, not fatal — the record is already in memory, and a demo bulletin's
/// durability is not worth aborting a running replica over.
fn append_journal(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    let write = || -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        f.write_all(&(bytes.len() as u32).to_le_bytes())?;
        f.write_all(bytes)?;
        f.sync_all()
    };
    if let Err(e) = write() {
        tracing::warn!("could not journal a record: {e}");
    }
}
