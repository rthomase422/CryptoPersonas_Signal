//! The serverless headless client (workstream **d4**).
//!
//! d3 built the [`Replica`]: ingest an ordered log of record *bytes*, apply the
//! deterministic accept rule, converge on the same bulletin as everyone else. d4 is
//! what makes that a **messenger** — it ties a [`Transport`] (the mock today, real
//! Signal under e2) to a replica:
//!
//! - records ride as chat messages ([`carriage`]);
//! - incoming messages are decoded and [`ingest`](Replica::ingest)ed, and the
//!   accepted log [`render`](render)ed as `~petname: message`;
//! - a co-located [`Member`] produces the records this client sends, proving against
//!   the replica's **own** Merkle trees (`SERVERLESS_PROTOCOL.md` §5);
//! - a late joiner adopts a [`Snapshot`] from their inviter, TOFU-pinned (§12).
//!
//! `Messenger` is where the send and receive halves meet. It is generic over the
//! three d1 tree heights, defaulting to the production heights; tests instantiate it
//! at tiny heights with in-process keygen, exactly as d3's do.
//!
//! # What d4 leaves to its neighbours
//!
//! - The barrier **cadence** — when [`barrier`](Messenger::barrier) fires — is d5.
//!   d4 exposes the trigger; d5 decides the heartbeat.
//! - `FoldScan` is off by default (§13); the [`carriage`] attachment path exists for
//!   it but nothing on the demo path produces one.
//! - The optimistic-object **re-base** loop (§13/O2) is `Member`'s noted seam: this
//!   client posts one interaction at a time and lets it land.

pub mod carriage;
pub mod heartbeat;
pub mod member;
pub mod render;
pub mod snapshot;

pub use heartbeat::Heartbeat;
pub use member::{Member, MemberError, MemberKeys};
pub use snapshot::{AdoptError, Snapshot};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use tokio::sync::Mutex;
use transport_api::{ConversationId, Incoming, Sent, Transport, TransportError};

use personas_bulletin::merkle::callback::{DEFAULT_CB_MEMB_HEIGHT, DEFAULT_CB_NMEMB_HEIGHT};
use personas_bulletin::merkle::MerkleObjStore;
use personas_bulletin::merkle::obj::DEFAULT_OBJ_HEIGHT;
use personas_bulletin::replica::record::{self, Ark, Eh, Flavour, PollKind, Record, SpentObject};
use personas_bulletin::replica::{
    Config, Replica, ReplicaKeys, Status, VIEW_CLAIM_LAG, ViewReport, SETTLE_LAG,
};
use personas_core::{F, persona};

use rand::{CryptoRng, RngCore};

/// A record could not be produced or sent.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// This messenger has no [`Member`] (an observer built from verifying keys only)
    /// and so cannot produce a proof-carrying record.
    #[error("this messenger is an observer (no member key) and cannot send")]
    Observer,
    #[error("a reset request's proof could not be read")]
    BadResetProof,
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error("could not encode a record: {0}")]
    Codec(#[from] record::CodecError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// An authorship proof could not be serialized. Distinct from `Codec`, which is
    /// about RECORD encoding — an authorship proof is not a record (see
    /// `Messenger::prove_authorship`).
    #[error("could not encode an authorship proof: {0}")]
    ProofCodec(#[from] ark_serialize::SerializationError),
    /// A rate-limited persona index at or above the per-context limit. Refused before
    /// anything is proved: every replica (ours included) would reject the post, and by
    /// then the member's object would already have moved past it.
    #[error("rate-limited persona #{number} does not exist: each context has {limit}")]
    PersonaIndexOutOfRange { number: u64, limit: usize },
    /// This member's object changed too recently to prove from: it is not yet in a
    /// settled root. Wait a barrier or two and try again.
    #[error("your last action is still settling")]
    Settling,
    /// A prepared scan is waiting to be committed or discarded; nothing else may be
    /// produced until it is (see [`Messenger::prepare_scan`]).
    #[error("a prepared scan is pending; commit or discard it first")]
    ScanPending,
    /// `commit_scan`/`discard_scan` with no prepared scan.
    #[error("no prepared scan")]
    NoPreparedScan,
}

/// A scan that has been proved but not yet released (see [`Messenger::prepare_scan`]).
struct PendingScan {
    emitted: Emitted,
    /// The member's object before the scan advanced it — restored by a discard.
    before: zk_callbacks::generic::user::User<F, personas_core::circuits::MsgUser>,
    /// The callback roots the proof pins; the scan is acceptable only while the
    /// replica's current roots still equal these.
    memb_root: F,
    nmemb_root: F,
}

/// How far into a barrier the barrier before it counts as settled. Records stamped just
/// before a boundary reach members well within this; one that takes longer can cost someone
/// a record, which they get back and send again ([`Messenger::take_lost`]). A schedule with
/// a period this short never gets there and stays at the full `SETTLE_LAG`.
pub const SETTLE_MARGIN_MS: u64 = 3_000;

/// A record of ours not yet settled, and the object it spent.
struct InFlight {
    eh: Eh,
    before: zk_callbacks::generic::user::User<F, personas_core::circuits::MsgUser>,
}

/// A record produced and folded into the sender's own replica, ready to broadcast.
///
/// Produced synchronously by the `emit_*` methods; the actual send is the async
/// [`broadcast`](Messenger::broadcast). Splitting them lets a test drive delivery
/// order by hand (the d3 convergence property) while the CLI just calls the
/// `send_*` convenience wrappers.
#[derive(Clone, Debug)]
pub struct Emitted {
    /// The encoded record bytes — what [`carriage`] packs into a chat message.
    pub bytes: Vec<u8>,
    /// Its envelope hash, the handle a caller uses to reference it (a ban poll's
    /// target, a rating's target).
    pub eh: Eh,
    /// The petname a transport shows in the sender slot, or `None` for anonymous.
    pub persona: Option<String>,
}

/// A serverless messenger: a [`Replica`], a [`Transport`], and optionally a
/// [`Member`] to send as.
pub struct Messenger<
    const OH: usize = DEFAULT_OBJ_HEIGHT,
    const MH: usize = DEFAULT_CB_MEMB_HEIGHT,
    const NH: usize = DEFAULT_CB_NMEMB_HEIGHT,
> {
    conversation: ConversationId,
    transport: Arc<dyn Transport>,
    replica: Replica<OH, MH, NH>,
    member: Option<Member>,
    /// The shared barrier schedule: how a delivered record's service timestamp maps to
    /// a settlement barrier (§14, d5). Defaults to [`Heartbeat::default`]; a live group
    /// sets its own anchor with [`with_heartbeat`](Self::with_heartbeat).
    heartbeat: Heartbeat,
    /// A proved scan not yet released (commit) or abandoned (discard).
    pending_scan: Option<PendingScan>,
    /// This member's newest object-changing record and the object it spent, until the
    /// record is settled. At most one: the next needs this one's object in a settled root.
    in_flight: Option<InFlight>,
    /// Records of ours the group lost, for the client to tell the member about.
    lost: Vec<Eh>,
    /// The barrier whose first [`SETTLE_MARGIN_MS`] have passed, by the clock `tick` reads.
    margin_passed: Option<u64>,
    /// When the operation under way started proving ([`OpTimings`]).
    op_started: Option<std::time::Instant>,
    /// How long the last operation took ([`last_op_timings`](Self::last_op_timings)).
    last_op: OpTimings,
    /// Records this member has already relayed after a view mismatch (§5.5); each is
    /// relayed at most once.
    relayed: std::collections::HashSet<Eh>,
    /// Whether view checking (§5.5) is on: our records carry view claims, we relay
    /// on a mismatch, and we accept relays. OFF by default (see
    /// [`with_view_checks`](Self::with_view_checks)).
    view_checks: bool,
}

/// How long the last operation took, split into PROVING (witness generation and the
/// Groth16 proof) and folding the result into our own replica (verify + apply), plus the
/// size of what it produced — for benchmarks and in-app experiment logs. Measuring costs
/// two clock reads per operation and changes nothing else.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpTimings {
    pub prove_us: u64,
    pub self_ingest_us: u64,
    pub bytes: usize,
}

fn micros_since(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

impl<const OH: usize, const MH: usize, const NH: usize> Messenger<OH, MH, NH> {
    /// A messenger over `transport`/`conversation` with a fresh in-memory replica and
    /// an optional member. Pass `None` for an observer (verify + render only).
    pub fn new(
        transport: Arc<dyn Transport>,
        conversation: impl Into<ConversationId>,
        keys: ReplicaKeys,
        config: Config,
        member: Option<Member>,
    ) -> Self {
        Self {
            conversation: conversation.into(),
            transport,
            replica: Replica::new(keys, config),
            member,
            heartbeat: Heartbeat::default(),
            pending_scan: None,
            in_flight: None,
            lost: Vec::new(),
            margin_passed: None,
            op_started: None,
            last_op: OpTimings::default(),
            relayed: Default::default(),
            view_checks: false,
        }
    }

    /// Turn view checking (§5.5) on or off. It is off by default while a privacy cost
    /// is reviewed: a view claim reveals which records its sender had seen, so a member
    /// who sends a record to one victim only can recognise the victim's next records
    /// until a relay heals the split (§5.5, "Tagging"). With it off, records carry no
    /// claim and encode exactly as before claims existed, nothing is relayed, received
    /// relays are ignored and [`view_report`](Self::view_report) is always empty.
    pub fn with_view_checks(mut self, on: bool) -> Self {
        self.view_checks = on;
        self
    }

    /// Set the barrier schedule this messenger buckets records against (§14). All
    /// members of a group must share the same [`Heartbeat`] (anchor + period), carried
    /// out of band like the genesis pin, or their settlement barriers will not line up.
    pub fn with_heartbeat(mut self, heartbeat: Heartbeat) -> Self {
        self.heartbeat = heartbeat;
        self
    }

    /// A messenger backed by a replica journal at `path` (records replayed on open).
    pub fn open(
        path: impl Into<std::path::PathBuf>,
        transport: Arc<dyn Transport>,
        conversation: impl Into<ConversationId>,
        keys: ReplicaKeys,
        config: Config,
        member: Option<Member>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            conversation: conversation.into(),
            transport,
            replica: Replica::open(path, keys, config)?,
            member,
            heartbeat: Heartbeat::default(),
            pending_scan: None,
            in_flight: None,
            lost: Vec::new(),
            margin_passed: None,
            op_started: None,
            last_op: OpTimings::default(),
            relayed: Default::default(),
            view_checks: false,
        })
    }

    /// Adopt a late-join [`Snapshot`] from your inviter (§12). Verifies the snapshot
    /// against the out-of-band genesis `pin` before replaying it, and re-derives all
    /// roots itself — so a snapshot that does not match the pin is refused, and one
    /// that lies self-reveals once this client starts proving.
    pub fn adopt(
        transport: Arc<dyn Transport>,
        conversation: impl Into<ConversationId>,
        keys: ReplicaKeys,
        config: Config,
        member: Option<Member>,
        snapshot: Snapshot,
        pin: &[u8; 32],
    ) -> Result<Self, AdoptError> {
        snapshot.verify(pin)?;
        let barrier = snapshot.barrier;
        let replica = Replica::from_records(keys, config, snapshot.into_records(), barrier);
        Ok(Self {
            conversation: conversation.into(),
            transport,
            replica,
            member,
            heartbeat: Heartbeat::default(),
            pending_scan: None,
            in_flight: None,
            lost: Vec::new(),
            margin_passed: None,
            op_started: None,
            last_op: OpTimings::default(),
            relayed: Default::default(),
            view_checks: false,
        })
    }

    /// Rebuild a messenger saved across a restart: the replica from its journalled
    /// `(first_barrier, bytes)` records at `current_barrier`, and the member (if any)
    /// restored by the caller with [`Member::from_state`]. Unlike [`adopt`](Self::adopt)
    /// there is no pin to check — these are this client's own records.
    pub fn restore(
        transport: Arc<dyn Transport>,
        conversation: impl Into<ConversationId>,
        keys: ReplicaKeys,
        config: Config,
        member: Option<Member>,
        records: Vec<(u64, Vec<u8>)>,
        current_barrier: u64,
    ) -> Self {
        Self {
            conversation: conversation.into(),
            transport,
            replica: Replica::from_records(keys, config, records, current_barrier),
            member,
            heartbeat: Heartbeat::default(),
            pending_scan: None,
            in_flight: None,
            lost: Vec::new(),
            margin_passed: None,
            op_started: None,
            last_op: OpTimings::default(),
            relayed: Default::default(),
            view_checks: false,
        }
    }

    // --- Accessors --------------------------------------------------------------

    pub fn replica(&self) -> &Replica<OH, MH, NH> {
        &self.replica
    }

    pub fn member(&self) -> Option<&Member> {
        self.member.as_ref()
    }

    /// The member's private state for saving ([`Member::export_state`]), or `None` for
    /// an observer. While a scan is pending this is the state BEFORE it: a prepared
    /// scan has revealed nothing, so the pre-scan object is still the unspent one.
    pub fn export_member_state(&self) -> Option<Result<Vec<u8>, SendError>> {
        let member = self.member.as_ref()?;
        Some(match &self.pending_scan {
            Some(pending) => member::export_user_state(&pending.before).map_err(SendError::from),
            None => member.export_state().map_err(SendError::from),
        })
    }

    /// Whether a scan would absorb anything now ([`Member::scan_needed`]).
    pub fn scan_needed(&self) -> bool {
        self.member
            .as_ref()
            .is_some_and(|m| m.scan_needed(self.replica.callback_store()))
    }

    /// Scans left in the sweep in progress ([`Member::sweep_remaining`]).
    /// Whether this member must finish a scan before its next post.
    pub fn scan_required(&self) -> bool {
        self.member.as_ref().is_some_and(Member::scan_required)
    }

    pub fn sweep_remaining(&self) -> usize {
        self.member.as_ref().map_or(0, Member::sweep_remaining)
    }

    /// Whether this member's current object is on the replica's object tree.
    pub fn member_on_bulletin(&self) -> bool {
        self.member
            .as_ref()
            .is_some_and(|m| m.is_on_bulletin(self.replica.obj_store()))
    }

    /// The barrier the shared schedule assigns to `now_ms`.
    pub fn barrier_at(&self, now_ms: u64) -> u64 {
        self.heartbeat.barrier_at(now_ms)
    }

    pub fn conversation(&self) -> &ConversationId {
        &self.conversation
    }

    /// The accepted chat log as display lines (`~petname: msg`, flagged where a
    /// persona was later revoked). See [`render`].
    pub fn render(&self) -> Vec<String> {
        render::render_log(self.replica.log())
    }

    /// The open and recently-closed polls as status lines.
    pub fn render_polls(&self) -> Vec<String> {
        render::render_polls(self.replica.derived())
    }

    /// A [`Snapshot`] of this replica, for handing to a late joiner. Share
    /// [`Snapshot::digest_hex`] out-of-band as the genesis pin.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot::new(
            self.replica.seen_with_barriers(),
            self.replica.current_barrier(),
        )
    }

    /// This replica's history for a LATE JOINER: every record with its first-seen
    /// barrier and real envelope hash, private text removed
    /// ([`Replica::catch_up_records`]).
    pub fn catch_up_records(&self) -> Vec<(u64, record::Eh, Vec<u8>)> {
        self.replica.catch_up_records()
    }

    /// Take in a history from [`catch_up_records`](Self::catch_up_records) (or a
    /// journal), with one rebuild, then cross to `at_barrier` (the barrier the history
    /// was taken at; never backwards). Returns how many records were new.
    pub fn import_records(
        &mut self,
        items: Vec<(u64, record::Eh, Vec<u8>)>,
        at_barrier: u64,
    ) -> usize {
        let added = self.replica.import_records(items);
        self.replica.advance_to(at_barrier);
        added
    }

    // --- Receive ----------------------------------------------------------------

    /// Ingest an incoming messenger event. Returns the accept-rule [`Status`] if the
    /// event carried a record, or `None` for ordinary chatter / a reaction (which the
    /// serverless protocol ignores — reputation is proof-carrying `Rate` records now,
    /// §10, not messenger reactions).
    pub fn ingest_incoming(
        &mut self,
        incoming: &Incoming,
    ) -> Option<Result<Status, record::CodecError>> {
        if let Incoming::Message { body, .. } = incoming
            && let Some((first_barrier, bytes)) = carriage::decode_relay(body)
        {
            let received_at = carriage::received_at(incoming);
            return Some(self.ingest_relayed(bytes, first_barrier, received_at));
        }
        let bytes = carriage::decode_incoming(incoming)?;
        match carriage::received_at(incoming) {
            // No service stamp (`0`, the sentinel): there is no shared clock to bucket by,
            // so fall back to the replica's local barrier — best-effort, delivery-timing
            // dependent. This is also the manual-cadence path the demo and tests drive with
            // explicit `barrier()` calls.
            0 => Some(self.replica.ingest(bytes)),
            // A real service timestamp: bucket by it, not by local receive timing — every
            // replica sees the same stamp, assigns the same barrier, and they converge
            // exactly (§4/§14, d5).
            received_at => {
                let first_barrier = self.heartbeat.barrier_at(received_at);
                Some(self.replica.ingest_at(bytes, first_barrier))
            }
        }
    }

    /// Ingest a record another member relayed (§5.5), placed at the barrier the relay
    /// names but never later than the relay message itself was serviced
    /// (`received_at_ms`, or our own barrier when there is no service stamp).
    pub fn ingest_relayed(
        &mut self,
        bytes: Vec<u8>,
        first_barrier: u64,
        received_at_ms: u64,
    ) -> Result<Status, record::CodecError> {
        if !self.view_checks {
            return Ok(Status::Rejected("view checks are off; relays are ignored"));
        }
        let latest = match received_at_ms {
            0 => self.replica.current_barrier(),
            at => self.heartbeat.barrier_at(at),
        };
        self.replica
            .ingest_relayed(bytes, first_barrier.min(latest))
    }

    // --- Views (§5.5) -----------------------------------------------------------

    /// How the views of the group carried by recent records compare with ours
    /// ([`Replica::view_report`]).
    pub fn view_report(&self) -> ViewReport {
        if !self.view_checks {
            return ViewReport::default();
        }
        self.replica.view_report()
    }

    /// The records to relay because of view mismatches, as `(first_barrier, bytes)`,
    /// each at most once.
    ///
    /// For a mismatch at barrier `b`, this member relays every relayable record it holds
    /// that was placed at `b - VIEW_CLAIM_LAG ..= b` (a join, re-join approval or admin
    /// ban cannot be relayed: see [`Record::relayable`]). Claims are made continuously, so a view that
    /// first differs at `b` most likely differs because of a record placed shortly
    /// before it. A member who was missing such a record receives it this way, and a
    /// member who is the one missing records receives the others' relays in turn. If
    /// the messenger drops the relays too, the mismatch persists and stays visible.
    pub fn take_relays(&mut self) -> Vec<(u64, Vec<u8>)> {
        if !self.view_checks {
            return Vec::new();
        }
        let report = self.replica.view_report();
        let mut barriers: Vec<u64> = report.mismatches.iter().map(|m| m.barrier).collect();
        barriers.dedup();
        let mut out = Vec::new();
        for b in barriers {
            for (first_barrier, bytes) in self
                .replica
                .relayable_between(b.saturating_sub(VIEW_CLAIM_LAG), b)
            {
                if self.relayed.insert(Eh::of_bytes(&bytes)) {
                    out.push((first_barrier, bytes));
                }
            }
        }
        out
    }

    /// The view claim to attach to a record we send now, if view checking is on.
    fn view_claim(&self) -> Option<record::ViewClaim> {
        self.view_checks
            .then(|| self.replica.view_claim())
            .flatten()
    }

    /// Relay every record [`take_relays`](Self::take_relays) returns. Returns how many.
    pub async fn broadcast_relays(&mut self) -> Result<usize, SendError> {
        let relays = self.take_relays();
        for (first_barrier, bytes) in &relays {
            let body = carriage::encode_relay(*first_barrier, bytes);
            let outgoing = transport_api::Outgoing::new(self.conversation.clone(), body);
            self.transport.send(outgoing).await?;
        }
        Ok(relays.len())
    }

    /// Cross exactly one barrier by hand: settle due tickets, close ban polls, re-pin
    /// the callback root (§5.2/§7). Used by tests and the CLI demo to drive settlement
    /// deterministically; the live cadence is [`tick`](Self::tick)/
    /// [`run_heartbeat`](Self::run_heartbeat).
    pub fn barrier(&mut self) {
        self.replica.barrier();
        self.check_in_flight();
    }

    /// Advance the replica to the barrier the shared schedule says `now_ms` (a
    /// service-comparable wall-clock time, ms since the epoch) has reached, settling any
    /// tickets now due. This is the sync core of the heartbeat; it reads a *local* clock
    /// only to move the monotone "how far has now got" counter, never to place a record
    /// (§14, d5). Returns the barrier the replica is now at.
    pub fn tick(&mut self, now_ms: u64) -> u64 {
        let barrier = self.heartbeat.barrier_at(now_ms);
        self.replica.advance_to(barrier);
        let margin_ago = self.heartbeat.barrier_at(now_ms.saturating_sub(SETTLE_MARGIN_MS));
        self.margin_passed = (margin_ago == barrier).then_some(barrier);
        self.check_in_flight();
        self.replica.current_barrier()
    }

    /// Drive the settlement heartbeat forever: every `heartbeat_secs` (the schedule's
    /// period) advance the replica to the current barrier and, when that actually
    /// crosses a boundary, call `on_barrier` so a UI can re-render.
    ///
    /// Shares the `Arc<Mutex<_>>` with [`receive_loop`](Self::receive_loop) — the two
    /// tasks run concurrently over one messenger, each taking the lock only briefly, so
    /// a barrier and an ingest never race. Spawn it alongside the receive loop and abort
    /// it when the client shuts down; it does not return on its own.
    pub async fn run_heartbeat(this: Arc<Mutex<Self>>, mut on_barrier: impl FnMut(&Self))
    where
        Self: Send,
    {
        let period = { this.lock().await.heartbeat.period_ms() };
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(period.max(1)));
        interval.tick().await; // the first tick fires immediately; skip it.
        loop {
            interval.tick().await;
            let now = now_ms();
            let mut m = this.lock().await;
            let before = m.replica.current_barrier();
            if m.tick(now) != before {
                on_barrier(&m);
            }
        }
    }

    // --- Send: produce (sync) ---------------------------------------------------

    /// Announce this member's join as `account`, proving its object is fresh. Must land
    /// before any other send. Accepted once per account, plus once per admin re-join
    /// approval ([`emit_rejoin_approve`](Self::emit_rejoin_approve)).
    pub fn emit_join(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        account: F,
    ) -> Result<Emitted, SendError> {
        if self.pending_scan.is_some() {
            return Err(SendError::ScanPending);
        }
        self.op_started = Some(std::time::Instant::now());
        let record = self
            .member
            .as_ref()
            .ok_or(SendError::Observer)?
            .join(rng, account)?;
        self.emit(record)
    }

    /// As a group admin, allow `account` one more join (after it asked for a reset).
    /// The client sends this under the admin's own account and every member checks the
    /// sender is an admin before ingesting it.
    /// As a group admin: ban the author of post `target` permanently, with no poll.
    /// Send it under the admin's OWN account: members only ingest it from an admin.
    pub fn emit_ban(&mut self, target: Eh) -> Result<Emitted, SendError> {
        if self.member.is_none() {
            return Err(SendError::Observer);
        }
        // No proof: nothing to time but the fold.
        self.op_started = None;
        self.emit(Record::Ban { target })
    }

    ///
    /// `proof` is the request's `not_banned_pred` proof, when it has one: approving spends
    /// the object it names.
    pub fn emit_rejoin_approve(
        &mut self,
        account: F,
        proof: Option<&[u8]>,
    ) -> Result<Emitted, SendError> {
        if self.member.is_none() {
            return Err(SendError::Observer);
        }
        let spent = proof
            .map(|bytes| {
                let (proof, inputs) = personas_core::decode_not_banned_proof(bytes)
                    .ok_or(SendError::BadResetProof)?;
                Ok::<_, SendError>(SpentObject {
                    nul: Ark(inputs[1]),
                    root: Ark(inputs[2]),
                    proof: Ark(proof),
                })
            })
            .transpose()?;
        // No proof to make: nothing to time but the fold.
        self.op_started = None;
        self.emit(Record::RejoinApprove {
            account: Ark(account),
            spent,
        })
    }

    /// Prove this member is not banned and has just completed a scan sweep, as
    /// `account`, against the replica's current root — the proof a reset request
    /// carries. Encoded as `personas_core::encode_not_banned_proof` (`[account, nul, root]`).
    pub fn prove_not_banned(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        account: F,
    ) -> Result<Vec<u8>, SendError> {
        let (nul, root, proof) = {
            let (_, settled, member) = self.parts_mut()?;
            member.not_banned(rng, settled, account)?
        };
        let out = personas_core::encode_not_banned_proof(&proof, &[account, nul, root])?;
        self.record_proof_only(out.len());
        Ok(out)
    }

    /// Start over with a fresh object under the same secret key, keeping the replica. Only useful once an admin approved a re-join for this account.
    pub fn reset_member(&mut self, rng: &mut (impl CryptoRng + RngCore)) -> Result<(), SendError> {
        if self.pending_scan.is_some() {
            return Err(SendError::ScanPending);
        }
        self.member.as_mut().ok_or(SendError::Observer)?.reset(rng);
        // Whatever was in flight belonged to the object this replaces.
        self.in_flight = None;
        Ok(())
    }

    /// Produce an anonymous post.
    pub fn emit_post_anon(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        body: impl Into<String>,
    ) -> Result<Emitted, SendError> {
        self.emit_spending(|_, settled, member| member.post_anon(rng, settled, body))
    }

    /// Produce a pseudonymous post under `context`.
    pub fn emit_post_pseudo(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        body: impl Into<String>,
        context: F,
    ) -> Result<Emitted, SendError> {
        self.emit_spending(|_, settled, member| member.post_pseudo(rng, settled, body, context))
    }

    /// Produce a rate-limited pseudonymous post (`i`-th persona for `context`).
    pub fn emit_post_pseudo_rate(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        body: impl Into<String>,
        context: F,
        i: F,
    ) -> Result<Emitted, SendError> {
        use ark_ff::PrimeField;
        let limit = personas_core::circuits::RATE_LIMITED_PERSONAS_PER_CONTEXT;
        if i.into_bigint() >= F::from(limit as u64).into_bigint() {
            return Err(SendError::PersonaIndexOutOfRange {
                // As the UI numbers them: index 0 is persona #1.
                number: i.into_bigint().0[0].saturating_add(1),
                limit,
            });
        }
        self.emit_spending(|_, settled, member| member.post_pseudo_rate(rng, settled, body, context, i))
    }

    /// Open a poll (no proof). `target` is the post under review for a ban poll.
    pub fn emit_poll(
        &mut self,
        question: impl Into<String>,
        options: Vec<String>,
        kind: PollKind,
        target: Option<Eh>,
    ) -> Result<Emitted, SendError> {
        // An observer may still open a poll (it carries no proof), but for symmetry
        // we require membership — a group's polls come from its members.
        if self.member.is_none() {
            return Err(SendError::Observer);
        }
        self.op_started = None;
        self.emit(member::open_poll(question, options, kind, target))
    }

    /// Cast a ballot in `poll`.
    pub fn emit_vote(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        poll: Eh,
        option: u32,
    ) -> Result<Emitted, SendError> {
        let record = self.prove_identity(|member, settled| member.vote(rng, settled, poll, option))?;
        self.emit(record)
    }

    /// Rate `target` by `delta` (§10).
    pub fn emit_rate(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        target: Eh,
        delta: i8,
    ) -> Result<Emitted, SendError> {
        let record = self.prove_identity(|member, settled| member.rate(rng, settled, target, delta))?;
        self.emit(record)
    }

    /// Prove that two of OUR pseudonyms share an author, returning the encoded proof
    /// and its public inputs.
    ///
    /// Not an `emit_*`: this produces no record and folds nothing into the replica. An
    /// authorship proof is a read-only statement about our object, so it needs no
    /// accept rule, no `Record` variant and no convergence story — it travels as
    /// display payload and each recipient verifies it independently.
    ///
    /// Both pseudonyms are identified by their CONTEXT; the claimed values are derived
    /// from our own secret key inside the proof, which is the whole content of the
    /// claim.
    pub fn prove_authorship(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        context_a: F,
        context_b: F,
    ) -> Result<Vec<u8>, SendError> {
        let (root, claimed_a, claimed_b, proof) = {
            let (_, settled, member) = self.parts_mut()?;
            member.authorship(rng, settled, context_a, context_b)?
        };
        // PUBLIC INPUT LAYOUT: pub_args first, THEN the membership root.
        //
        // `[ctx_a, claimed_a, ctx_b, claimed_b, obj_root]`. The first four are the
        // order `PseudonymArgsPairVar`'s AllocVar allocates (circuits.rs: a.context,
        // a.claimed, b.context, b.claimed); the root comes last because
        // `prove_statement_and_in` against a MERKLE store allocates the membership root
        // as a public input after the predicate's own arguments. The replica documents
        // and relies on exactly this convention for the single-pseudonym case:
        // "[context, claimed, obj_root] — pub_args first, then the membership root"
        // (replica/mod.rs, `memo_predicate`).
        //
        // Omitting the root was the original bug here. It produced a proof that
        // generated fine and then failed verification every time, because the verifier
        // was handed four inputs for a five-input statement. The as-a-service
        // `make_authorship_proof` really does use four — but it proves against a
        // SIGNATURE-based store, which exposes membership differently, so copying its
        // layout into the Merkle path was wrong.
        let inputs = [context_a, claimed_a, context_b, claimed_b, root];
        let out = personas_core::encode_authorship_proof(&proof, &inputs)?;
        self.record_proof_only(out.len());
        Ok(out)
    }

    /// Emit a badge REQUEST (files the ticket an approver invokes).
    pub fn emit_badge_request(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        slot: u8,
    ) -> Result<Emitted, SendError> {
        self.emit_spending(|_, settled, member| member.badge_request(rng, settled, slot))
    }

    /// Emit an APPROVAL of a badge request, naming the request's envelope hash.
    ///
    /// Needs no member proof — it is an admin's say-so — but still goes through `emit`
    /// so every replica folds it in and reaches the same verdict.
    pub fn emit_badge_approve(&mut self, target: Eh, slot: u8) -> Result<Emitted, SendError> {
        // No proof: nothing to time but the fold.
        self.op_started = None;
        self.emit(Record::BadgeApprove { target, slot })
    }

    /// Prove we hold `badge` in slot `i`, returning the encoded proof and its public
    /// inputs `[i, claimed, obj_root]`.
    ///
    /// Same shape as `prove_authorship`: read-only, no record, no accept rule. The badge
    /// itself must already be in our object — it gets there only when an approver
    /// invokes our callback with a BADGE flag and we then scan.
    pub fn prove_badge(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        i: F,
        badge: F,
    ) -> Result<Vec<u8>, SendError> {
        let (root, proof) = {
            let (_, settled, member) = self.parts_mut()?;
            member.badge(rng, settled, i, badge)?
        };
        // pub_args first, then the root — the Merkle convention.
        let out = personas_core::encode_badge_proof(&proof, &[i, badge, root])?;
        self.record_proof_only(out.len());
        Ok(out)
    }

    /// Produce a scan absorbing every callback invoked on this member since its last
    /// scan, against the replica's current-barrier callback set (§5.2).
    pub fn emit_scan(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Emitted, SendError> {
        self.emit_spending(|replica, settled, member| {
            member.scan(rng, settled, replica.callback_store())
        })
    }

    // --- Send: a scan that can be checked before it is released (§5.2) ----------
    //
    // A scan pins the replica's CURRENT callback roots, and every replica rejects it if
    // a settlement re-pinned them before the scan's barrier ("scan names a superseded
    // barrier"). Proving takes seconds, so a scan can go stale while it is being made.
    // A stale scan that is SENT is the dangerous case: it reveals the member's nullifier,
    // every replica rejects it, and the member's local object has nevertheless advanced
    // past it.
    //
    // So a scan is produced in two steps. `prepare_scan` proves it and advances the
    // object but releases nothing; the caller checks `scan_still_valid` (after waiting
    // out a barrier boundary if one is close) and then either `commit_scan`s — which
    // folds it into the replica and only now hands over the bytes to send — or
    // `discard_scan`s, which restores the pre-scan object. A discard can only happen
    // before commit, i.e. before the bytes exist outside this struct, so the nullifier a
    // discarded scan would have revealed has never been revealed, and the restored
    // object is safe to spend. Nothing else can be produced while a scan is pending.

    /// Prove a scan without releasing it. Returns its envelope hash only. A `dummy` scan
    /// changes nothing and only fills this member's count of scans for the epoch.
    pub fn prepare_scan(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        dummy: bool,
    ) -> Result<Eh, SendError> {
        let (record, before, memb_root, nmemb_root) = {
            let (replica, settled, member) = self.parts_mut()?;
            let before = member.user.clone();
            let cbs = replica.callback_store();
            let (memb_root, nmemb_root) = (cbs.memb_root(), cbs.nmemb_root());
            let record = if dummy {
                member.dummy_scan(rng, settled, cbs)?
            } else {
                member.scan(rng, settled, cbs)?
            };
            (record, before, memb_root, nmemb_root)
        };
        let (bytes, eh) = record::encode_with_view(&record, self.view_claim())?;
        self.last_op = OpTimings {
            prove_us: self.op_started.take().map_or(0, micros_since),
            self_ingest_us: 0,
            bytes: bytes.len(),
        };
        self.pending_scan = Some(PendingScan {
            emitted: Emitted {
                bytes,
                eh,
                persona: None,
            },
            before,
            memb_root,
            nmemb_root,
        });
        Ok(eh)
    }

    /// Whether the prepared scan would still be accepted at the replica's current
    /// barrier: its pinned callback roots are still the current ones.
    pub fn scan_still_valid(&self) -> bool {
        self.pending_scan.as_ref().is_some_and(|p| {
            let cbs = self.replica.callback_store();
            p.memb_root == cbs.memb_root() && p.nmemb_root == cbs.nmemb_root()
        })
    }

    /// Release the prepared scan: fold it into our replica and return it to send. After
    /// this it can no longer be discarded.
    pub fn commit_scan(&mut self) -> Result<Emitted, SendError> {
        let pending = self.pending_scan.take().ok_or(SendError::NoPreparedScan)?;
        let started = std::time::Instant::now();
        let _ = self.replica.ingest(pending.emitted.bytes.clone());
        self.last_op.self_ingest_us = micros_since(started);
        self.in_flight = Some(InFlight {
            eh: pending.emitted.eh,
            before: pending.before,
        });
        Ok(pending.emitted)
    }

    /// Abandon the prepared scan and restore the object it advanced. Safe only because
    /// the scan was never released (see above).
    pub fn discard_scan(&mut self) -> Result<(), SendError> {
        let pending = self.pending_scan.take().ok_or(SendError::NoPreparedScan)?;
        let member = self.member.as_mut().ok_or(SendError::Observer)?;
        member.user = pending.before;
        Ok(())
    }

    // --- Send: broadcast (async) ------------------------------------------------

    /// Broadcast an already-[`emit`](Self::emit_join)ted record over the transport.
    pub async fn broadcast(&self, emitted: &Emitted) -> Result<Sent, SendError> {
        let carried = carriage::encode(&emitted.bytes);
        let outgoing = carried.into_outgoing(self.conversation.clone(), emitted.persona.clone());
        let transport = self.transport.clone();
        Ok(transport.send(outgoing).await?)
    }

    /// Emit and broadcast an anonymous post in one call. Returns its `eh` (to
    /// reference later) and the messenger's `Sent` id.
    pub async fn send_post_anon(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        body: impl Into<String>,
    ) -> Result<(Eh, Sent), SendError> {
        let e = self.emit_post_anon(rng, body)?;
        let sent = self.broadcast(&e).await?;
        Ok((e.eh, sent))
    }

    /// Emit and broadcast a pseudonymous post.
    pub async fn send_post_pseudo(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        body: impl Into<String>,
        context: F,
    ) -> Result<(Eh, Sent), SendError> {
        let e = self.emit_post_pseudo(rng, body, context)?;
        let sent = self.broadcast(&e).await?;
        Ok((e.eh, sent))
    }

    /// Emit and broadcast this member's join as `account`.
    pub async fn send_join(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        account: F,
    ) -> Result<(Eh, Sent), SendError> {
        let e = self.emit_join(rng, account)?;
        let sent = self.broadcast(&e).await?;
        Ok((e.eh, sent))
    }

    /// Emit and broadcast a poll.
    pub async fn send_poll(
        &mut self,
        question: impl Into<String>,
        options: Vec<String>,
        kind: PollKind,
        target: Option<Eh>,
    ) -> Result<(Eh, Sent), SendError> {
        let e = self.emit_poll(question, options, kind, target)?;
        let sent = self.broadcast(&e).await?;
        Ok((e.eh, sent))
    }

    /// Emit and broadcast a ballot.
    pub async fn send_vote(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        poll: Eh,
        option: u32,
    ) -> Result<(Eh, Sent), SendError> {
        let e = self.emit_vote(rng, poll, option)?;
        let sent = self.broadcast(&e).await?;
        Ok((e.eh, sent))
    }

    // --- The receive loop -------------------------------------------------------

    /// Subscribe to the transport and ingest every record it delivers, calling
    /// `on_update` after each accepted record so a UI can re-render.
    ///
    /// Shared behind an `Arc<Mutex<_>>` so a caller can hold the same messenger to
    /// send from another task; the loop takes the lock only briefly per event. Ends
    /// when the transport stream closes.
    pub async fn receive_loop(
        this: Arc<Mutex<Self>>,
        mut on_update: impl FnMut(&Self),
    ) -> Result<(), TransportError>
    where
        Self: Send,
    {
        let transport = { this.lock().await.transport.clone() };
        let mut stream = transport.subscribe().await?;
        while let Some(event) = stream.next().await {
            let mut m = this.lock().await;
            if m.ingest_incoming(&event).is_some() {
                // Relays are best effort: a failed send leaves the mismatch visible.
                let _ = m.broadcast_relays().await;
                on_update(&m);
            }
        }
        Ok(())
    }

    // --- Internals --------------------------------------------------------------

    /// Encode a produced record, fold it into the sender's *own* replica (a sender is
    /// a member of its own log), and return it ready to broadcast.
    fn emit(&mut self, record: Record) -> Result<Emitted, SendError> {
        if self.pending_scan.is_some() {
            return Err(SendError::ScanPending);
        }
        let prove_us = self.op_started.take().map_or(0, micros_since);
        // Every record carries the sender's view of the group, so receivers can check
        // that the messenger showed everyone the same records (§5.5).
        let (bytes, eh) = record::encode_with_view(&record, self.view_claim())?;
        let persona = persona_for(&record);
        // Idempotent by `eh`, so the echo the transport later delivers is deduped.
        let started = std::time::Instant::now();
        let _ = self.replica.ingest(bytes.clone());
        self.last_op = OpTimings {
            prove_us,
            self_ingest_us: micros_since(started),
            bytes: bytes.len(),
        };
        Ok(Emitted { bytes, eh, persona })
    }

    /// Timings of the last operation ([`OpTimings`]).
    pub fn last_op_timings(&self) -> OpTimings {
        self.last_op
    }

    // A proof that is not a record (authorship, badge possession, not banned): proving
    // only, nothing folded into the replica.
    fn record_proof_only(&mut self, bytes: usize) {
        self.last_op = OpTimings {
            prove_us: self.op_started.take().map_or(0, micros_since),
            self_ingest_us: 0,
            bytes,
        };
    }

    /// Split the disjoint `replica`/`member` fields so a produce step can read the
    /// object tree while mutating the member's user state.
    fn parts_mut(
        &mut self,
    ) -> Result<(&Replica<OH, MH, NH>, &MerkleObjStore<F, OH>, &mut Member), SendError> {
        // Every proving flow comes through here: none may run on top of a pending scan.
        if self.pending_scan.is_some() {
            return Err(SendError::ScanPending);
        }
        // ...so this is where proving starts, for OpTimings.
        self.op_started = Some(std::time::Instant::now());
        let lag = self.proving_lag();
        let member = self.member.as_mut().ok_or(SendError::Observer)?;
        let settled = self.replica.proving_store_at(lag).ok_or(SendError::Settling)?;
        if !member.is_on_bulletin(settled) {
            return Err(if member.is_on_bulletin(self.replica.obj_store()) {
                SendError::Settling
            } else {
                MemberError::NotJoined.into()
            });
        }
        Ok((&self.replica, settled, member))
    }

    /// Run a producer of an object-changing record, keeping the object it spends so a
    /// lost record can be taken back ([`Messenger::take_lost`]).
    fn emit_spending(
        &mut self,
        produce: impl FnOnce(&Replica<OH, MH, NH>, &MerkleObjStore<F, OH>, &mut Member) -> Result<Record, MemberError>,
    ) -> Result<Emitted, SendError> {
        let (record, before) = {
            let (replica, settled, member) = self.parts_mut()?;
            let before = member.user.clone();
            (produce(replica, settled, member)?, before)
        };
        let emitted = self.emit(record)?;
        self.in_flight = Some(InFlight {
            eh: emitted.eh,
            before,
        });
        Ok(emitted)
    }

    fn proving_lag(&self) -> u64 {
        match self.margin_passed {
            Some(barrier) if barrier == self.replica.current_barrier() => 1,
            _ => SETTLE_LAG,
        }
    }

    /// Whether this member could prove right now: its object is in a settled root.
    pub fn is_settled(&self) -> bool {
        self.member.as_ref().is_some_and(|m| {
            self.replica
                .proving_store_at(self.proving_lag())
                .is_some_and(|settled| m.is_on_bulletin(settled))
        })
    }

    /// Whether this member could vote or rate right now, which needs a settled object but
    /// not its newest one ([`Messenger::prove_identity`]).
    pub fn can_prove_identity(&self) -> bool {
        self.is_settled()
            || self.in_flight.as_ref().is_some_and(|in_flight| {
                self.replica
                    .proving_store_at(self.proving_lag())
                    .is_some_and(|settled| member::object_on_bulletin(&in_flight.before, settled))
            })
    }

    /// Prove something that spends nothing, a vote or a rating. Such a proof shows who a
    /// member is, not what its object holds, and every object of a member shares one key
    /// and so one pseudonym. So while the newest object settles, the one before it serves:
    /// the member need not wait and still gets one ballot or rating.
    fn prove_identity(
        &mut self,
        prove: impl FnOnce(&Member, &MerkleObjStore<F, OH>) -> Result<Record, MemberError>,
    ) -> Result<Record, SendError> {
        if self.pending_scan.is_some() {
            return Err(SendError::ScanPending);
        }
        self.op_started = Some(std::time::Instant::now());
        let lag = self.proving_lag();
        let settled = self.replica.proving_store_at(lag).ok_or(SendError::Settling)?;
        let member = self.member.as_mut().ok_or(SendError::Observer)?;
        if member.is_on_bulletin(settled) {
            return Ok(prove(member, settled)?);
        }
        let Some(in_flight) = &self.in_flight else {
            return Err(if member.is_on_bulletin(self.replica.obj_store()) {
                SendError::Settling
            } else {
                MemberError::NotJoined.into()
            });
        };
        let newest = std::mem::replace(&mut member.user, in_flight.before.clone());
        let proved = prove(member, settled);
        member.user = newest;
        Ok(proved?)
    }

    /// The re-base (§13). If the group lost this member's newest record, no replica will
    /// ever apply it, so its nullifier is unspent and the object it spent is still the
    /// member's: go back to it, or the member would be stranded on an object that does
    /// not exist. Called on every tick.
    fn check_in_flight(&mut self) {
        let Some(in_flight) = &self.in_flight else {
            return;
        };
        if self.replica.is_lost(&in_flight.eh) {
            let in_flight = self.in_flight.take().expect("just checked");
            if let Some(member) = self.member.as_mut() {
                member.user = in_flight.before;
            }
            self.lost.push(in_flight.eh);
        } else if self.is_settled() {
            self.in_flight = None;
        }
    }

    /// Records of ours the group lost since the last call. The member's object is already
    /// back where it was; what remains is telling them, so they can send again.
    pub fn take_lost(&mut self) -> Vec<Eh> {
        std::mem::take(&mut self.lost)
    }

    /// How many records from others name a root we never produced ([`Replica::foreign_roots`]).
    pub fn foreign_roots(&self) -> usize {
        self.replica.foreign_roots()
    }
}

/// Local wall-clock milliseconds since the Unix epoch — the heartbeat's tick source.
/// Comparable to a provider's service timestamps (both count from the same epoch), and
/// used only to advance the monotone barrier counter (§14, d5).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The petname a record should render its sender as (a pseudonymous post's persona),
/// or `None` for an anonymous or non-post record.
fn persona_for(record: &Record) -> Option<String> {
    match record {
        Record::Post {
            flavour: Flavour::Pseudo | Flavour::PseudoRate,
            extra,
            ..
        } => extra.0.get(1).map(|claimed| persona::petname(*claimed)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
