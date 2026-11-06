//! Personas Node/Electron native addon (workstream **e2**).
//!
//! A napi-rs cdylib exposing the **transport-agnostic** personas ZK engine — a
//! [`Messenger`] (a d3 [`Replica`] plus an optional [`Member`] to send as) over
//! record bytes — to Signal-Desktop. There is **no Signal crypto here**: emit
//! produces the CBOR record with its real Groth16 proof (the *plaintext* Desktop
//! then encrypts and delivers over its own libsignal), and ingest verifies + folds
//! a record that arrived over Desktop. Delivery, sealed sender, and the shared
//! phantom identity all live on the Desktop side.
//!
//! Everything the renderer touches is a plain JS value (strings, numbers, Buffers,
//! objects); `Eh` handles cross the boundary as lowercase hex. The heavy proving
//! path is synchronous today (the `Messenger` send-side used by Desktop is not the
//! async transport path) — proof-gen offloading off the main thread is layered in
//! where the renderer would otherwise stall.

use std::sync::Arc;

use ark_serialize::CanonicalSerialize;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use rand::SeedableRng;
use rand::rngs::StdRng;

use personas_bulletin::merkle::params::ensure_merkle_keys;
use personas_bulletin::replica::record::{Eh, PollKind};
use personas_bulletin::replica::{Config as ReplicaConfig, ReplicaKeys, Status};
use personas_core::F;
use personas_messenger::{Emitted, Heartbeat, Member, MemberKeys, Messenger, carriage};
use transport_api::{ConversationId, Incoming, MessageId, Transport};
use transport_mock::MockTransport;

// The production Merkle heights `ensure_merkle_keys` generates keys for; the
// engine's `Messenger` must be instantiated at exactly these (see personas-bulletin
// obj.rs / callback.rs `DEFAULT_*_HEIGHT`).
type Engine32 = Messenger<32, 32, 32>;

/// Options for [`Engine::new`].
#[napi(object)]
pub struct EngineOptions {
    /// Directory holding (or to generate) the ~51 MB Merkle-mode Groth16 key
    /// bundle. The first engine to touch a fresh dir pays the (minutes-long) keygen;
    /// every later one loads the cache in ~100 ms. Share one dir across members.
    pub data_dir: String,
    /// Conversation id this engine's records belong to. Defaults to
    /// `"personas"`.
    pub conversation: Option<String>,
    /// `true` (default) builds a member that can emit; `false` builds an observer
    /// that can only verify + render.
    pub member: Option<bool>,
    /// Optional deterministic RNG seed (for reproducible benchmarks/tests). Omit for
    /// OS entropy.
    pub seed: Option<f64>,
    /// Replica accept-rule config; each defaults to the demo values
    /// (`root_window: 256`, a 48-hour ban window, 24-hour polls).
    pub root_window: Option<u32>,
    pub settlement_barriers: Option<u32>,
    pub poll_close_barriers: Option<u32>,
    /// Shared barrier schedule (§14). Set both to bucket ingests by service
    /// timestamp; omit for the default (local-barrier) cadence the tests/demo drive
    /// with explicit `barrier()` calls.
    pub heartbeat_anchor_ms: Option<f64>,
    pub heartbeat_period_ms: Option<f64>,
    /// View checking (`SERVERLESS_PROTOCOL.md` §5.5): records carry the sender's view
    /// of the group, mismatches are reported and missing records relayed. Default
    /// `false`, pending review of its privacy cost (§5.5, "Tagging").
    pub view_checks: Option<bool>,
    /// A member's saved private state ([`Engine::export_member_state`]) to continue as,
    /// instead of minting a new member. Ignored for an observer.
    pub member_state: Option<Buffer>,
    /// A file to journal every seen record to (with its barrier), and to restore the
    /// replica from at construction. Public data: the records every member holds.
    pub journal_path: Option<String>,
}

/// A record produced by an `emit*` call: the CBOR bytes to carry, its envelope
/// hash (the handle for polls/ratings), and the petname to show in the sender slot.
/// A badge request the admin has not approved yet.
#[napi(object)]
pub struct JsBadgeRequest {
    /// Envelope hash of the request record — what `emitBadgeApprove` takes.
    pub eh: String,
    /// 1 = Faculty, 2 = Student, 3 = Industry.
    pub slot: u32,
}

/// The two petnames an authorship proof actually proves about.
///
/// Derived from the proof's own public inputs by `Engine::verify_authorship`. A caller
/// that renders these is sound; one that renders names taken from the wire is not.
#[napi(object)]
pub struct JsAuthorship {
    pub first: String,
    pub second: String,
}

#[napi(object)]
pub struct JsEmitted {
    pub bytes: Buffer,
    pub eh: String,
    pub persona: Option<String>,
}

/// The accept-rule outcome of an ingest.
#[napi(object)]
pub struct JsStatus {
    /// `"applied"`, `"buffered"`, or `"rejected"`.
    pub status: String,
    /// The rejection reason when `status == "rejected"`.
    pub reason: Option<String>,
    /// The ingested record's envelope hash (hex) — look up the resulting chat-log
    /// entry with [`Engine::log_entry`]. Empty if the bytes did not decode.
    pub eh: String,
}

/// How the views of the group carried by recent records compare with ours
/// (`SERVERLESS_PROTOCOL.md` §5.5).
#[napi(object)]
pub struct JsViewReport {
    /// Some member saw a different set of records than we did. Show the user.
    pub diverged: bool,
    /// Claims that match our view.
    pub agreeing: u32,
    /// Claims too recent to check yet.
    pub pending: u32,
    /// The records whose claims disagree, oldest barrier first.
    pub mismatches: Vec<JsViewMismatch>,
}

#[napi(object)]
pub struct JsViewMismatch {
    pub barrier: f64,
    /// Envelope hash (hex) of the record that carried the disagreeing claim.
    pub eh: String,
}

/// A record to relay to the group because views disagree ([`Engine::take_relays`]).
#[napi(object)]
pub struct JsRelay {
    /// The barrier we placed the record at; send it alongside the record.
    pub barrier: f64,
    pub record: Buffer,
}

/// One rendered chat-log line, structured for the UI (Phase 4).
#[napi(object)]
pub struct JsLogEntry {
    pub eh: String,
    pub kind: String,
    /// The persona petname, or `None` for an anonymous post.
    pub author: Option<String>,
    pub body: String,
    /// `true` once the author's persona was revoked by a settled ban — render the
    /// post flagged, never delete it (the rendering gate).
    pub flagged: bool,
}

/// How long the last operation took (personas_messenger::OpTimings), in milliseconds.
#[napi(object)]
pub struct JsOpTimings {
    /// Proof generation (witness + Groth16 proof).
    pub prove_ms: f64,
    /// Folding the record into our own replica (verify + apply).
    pub self_ingest_ms: f64,
    /// Size of the record or proof produced.
    pub bytes: u32,
}

/// The latest settlement barrier that invoked callbacks, and what it cost.
#[napi(object)]
pub struct JsSettleTimings {
    pub barrier: f64,
    pub invoked: u32,
    /// Invoking the callbacks ("post callback"), all of them.
    pub invoke_ms: f64,
    /// The epoch update that follows (re-pinning the non-membership root).
    pub epoch_update_ms: f64,
}

/// Joins applied and re-joins approved for one account.
#[napi(object)]
pub struct JsJoinCounts {
    pub joins: u32,
    pub approved: u32,
}

/// The account a join or re-join approval names, and which kind it is.
/// A poll's text and kind, read from its record.
#[napi(object)]
pub struct JsPollText {
    pub question: String,
    pub options: Vec<String>,
    /// `"ban"` or `"standard"`.
    pub kind: String,
}

#[napi(object)]
pub struct JsAccountClaim {
    /// `"join"`, `"rejoin-approve"` or `"ban"`.
    pub kind: String,
    /// The account's ACI as 32 hex characters (no dashes); empty for a ban.
    pub account: String,
}

/// An account as the engine's field element, from the ACI's 32 hex characters.
fn account_from_hex(account: &str) -> napi::Result<F> {
    let bytes = hex::decode(account.replace('-', ""))
        .map_err(|e| napi::Error::from_reason(format!("bad account hex: {e}")))?;
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|_| napi::Error::from_reason("an account is 16 bytes (an ACI)"))?;
    Ok(personas_core::account_field(&arr))
}

/// The personas ZK engine: a production-height messenger plus its RNG.
#[napi]
pub struct Engine {
    inner: Engine32,
    rng: StdRng,
    /// Verifying key for `authorship_pred`, kept so a RECIPIENT can check an authorship
    /// proof. It ships in the same `ServerKeys` bundle every instance already generates,
    /// so holding it costs nothing extra.
    authorship_vk: personas_core::PreparedVk,
    /// Verifying key for `badge_pred`, so a recipient can check a badge proof.
    badge_vk: personas_core::PreparedVk,
    /// Verifying key for `not_banned_pred`, so an admin can check a reset request.
    not_banned_vk: personas_core::PreparedVk,
    /// The record journal, when persistence is on.
    journal: Option<Journal>,
}

/// An append-only file of `(first_barrier, record)` entries — everything needed to
/// rebuild the replica after a restart ([`Messenger::restore`]). A record is appended
/// again when its barrier changes (an authoritative re-ingest); the last entry wins.
///
/// Layout: `PZJ1`, then entries of `[u64 LE barrier][u32 LE length][record bytes]`. A
/// torn final entry (a crash mid-append) is ignored on read.
///
/// A record taken in from a late-join history has its private text removed, so its
/// bytes no longer hash to its envelope hash. Such an entry sets the top bit of the
/// barrier and carries the real hash (32 bytes) between the length and the bytes.
struct Journal {
    file: std::fs::File,
    written: std::collections::HashMap<Eh, u64>,
}

const JOURNAL_MAGIC: &[u8; 4] = b"PZJ1";
/// Set on a journal entry's barrier when the entry carries its envelope hash.
const JOURNAL_EH_FLAG: u64 = 1 << 63;
/// A late-join history (`export_catch_up`): `PZH1`, the barrier it was taken at, then
/// entries of `[u64 LE barrier][32-byte eh][u32 LE length][record bytes]`.
const CATCH_UP_MAGIC: &[u8; 4] = b"PZH1";

/// A journaled record: `(barrier, eh, bytes)`.
type JournalEntry = (u64, Eh, Vec<u8>);

impl Journal {
    /// Open (creating if needed) and read back the records, last entry per record wins.
    fn open(path: &str) -> std::io::Result<(Self, Vec<JournalEntry>)> {
        use std::io::{Read, Write};
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;
        if raw.is_empty() {
            file.write_all(JOURNAL_MAGIC)?;
            file.sync_data()?;
        } else if raw.len() < 4 || &raw[..4] != JOURNAL_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a personas record journal",
            ));
        }
        let mut latest: std::collections::BTreeMap<Eh, (u64, Vec<u8>)> =
            std::collections::BTreeMap::new();
        let mut at = 4;
        while raw.len() >= at + 12 {
            let tagged = u64::from_le_bytes(raw[at..at + 8].try_into().expect("8 bytes"));
            let len =
                u32::from_le_bytes(raw[at + 8..at + 12].try_into().expect("4 bytes")) as usize;
            let (barrier, given_eh, start) = if tagged & JOURNAL_EH_FLAG != 0 {
                let Some(eh) = raw.get(at + 12..at + 44) else {
                    break; // torn tail
                };
                (
                    tagged & !JOURNAL_EH_FLAG,
                    Some(Eh(eh.try_into().expect("32 bytes"))),
                    at + 44,
                )
            } else {
                (tagged, None, at + 12)
            };
            let Some(bytes) = raw.get(start..start + len) else {
                break; // torn tail
            };
            if let Ok((_, computed)) = personas_bulletin::replica::record::decode(bytes) {
                latest.insert(given_eh.unwrap_or(computed), (barrier, bytes.to_vec()));
            }
            at = start + len;
        }
        let written = latest.iter().map(|(eh, (b, _))| (*eh, *b)).collect();
        let records = latest
            .into_iter()
            .map(|(eh, (barrier, bytes))| (barrier, eh, bytes))
            .collect();
        Ok((Self { file, written }, records))
    }

    /// Append `bytes` at `barrier` unless that is already what the journal holds.
    fn record(&mut self, eh: Eh, barrier: u64, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        if self.written.get(&eh) == Some(&barrier) {
            return Ok(());
        }
        let mut entry = Vec::with_capacity(44 + bytes.len());
        let own_identity = personas_bulletin::replica::record::decode(bytes)
            .is_ok_and(|(_, computed)| computed == eh);
        if own_identity {
            entry.extend_from_slice(&barrier.to_le_bytes());
            entry.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        } else {
            // A stripped late-join record: keep its real hash beside it.
            entry.extend_from_slice(&(barrier | JOURNAL_EH_FLAG).to_le_bytes());
            entry.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            entry.extend_from_slice(&eh.0);
        }
        entry.extend_from_slice(bytes);
        self.file.write_all(&entry)?;
        self.file.sync_data()?;
        self.written.insert(eh, barrier);
        Ok(())
    }
}

fn eh_to_hex(eh: &Eh) -> String {
    hex::encode(eh.0)
}

fn eh_from_hex(s: &str) -> napi::Result<Eh> {
    let bytes = hex::decode(s).map_err(|e| napi::Error::from_reason(format!("bad eh hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| napi::Error::from_reason("eh must be 32 bytes"))?;
    Ok(Eh(arr))
}

fn to_emitted(e: Emitted) -> JsEmitted {
    JsEmitted {
        eh: eh_to_hex(&e.eh),
        persona: e.persona,
        bytes: Buffer::from(e.bytes),
    }
}

fn root_hex(root: &F) -> String {
    let mut buf = Vec::new();
    // Infallible for a field element into a Vec.
    root.serialize_compressed(&mut buf).expect("serialize F");
    hex::encode(buf)
}

#[napi]
impl Engine {
    /// Build an engine: prepare/load the Merkle keys under `data_dir`, then stand up
    /// a `Messenger<32,32,32>` with a null transport (Desktop is the real transport).
    #[napi(constructor)]
    pub fn new(options: EngineOptions) -> napi::Result<Self> {
        let keys = ensure_merkle_keys(std::path::Path::new(&options.data_dir))
            .map_err(|e| napi::Error::from_reason(format!("ensure_merkle_keys: {e}")))?;
        let replica_keys = ReplicaKeys::from_server_keys(&keys);

        let mut rng = match options.seed {
            Some(seed) => StdRng::seed_from_u64(seed as u64),
            None => StdRng::from_entropy(),
        };

        let is_member = options.member.unwrap_or(true);
        let member = if is_member {
            let member_keys = MemberKeys::from_server_keys(&keys);
            Some(match &options.member_state {
                Some(state) => Member::from_state(state.as_ref(), member_keys).map_err(|e| {
                    napi::Error::from_reason(format!("member_state is unreadable: {e}"))
                })?,
                None => Member::create(member_keys, &mut rng),
            })
        } else {
            None
        };

        // The windows are durations, so they follow the group's barrier period.
        let deployed = ReplicaConfig::for_period_ms(
            options
                .heartbeat_period_ms
                .map_or(personas_bulletin::replica::DEFAULT_BARRIER_PERIOD_MS, |p| p as u64),
        );
        let config = ReplicaConfig {
            root_window: options
                .root_window
                .map_or(deployed.root_window, |n| n as usize),
            settlement_barriers: options
                .settlement_barriers
                .map_or(deployed.settlement_barriers, u64::from),
            poll_close_barriers: options
                .poll_close_barriers
                .map_or(deployed.poll_close_barriers, u64::from),
        };

        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let conversation =
            ConversationId(options.conversation.unwrap_or_else(|| "personas".into()));

        // Prepared once for verification (personas_core::verify): same checks, without
        // re-preparing the key on every proof.
        let authorship_vk = personas_core::PreparedVk::new(&keys.authorship_pred_verifying_key);
        let badge_vk = personas_core::PreparedVk::new(&keys.badge_pred_verifying_key);
        let not_banned_vk = personas_core::PreparedVk::new(&keys.not_banned_pred_verifying_key);

        let heartbeat = match (options.heartbeat_anchor_ms, options.heartbeat_period_ms) {
            (Some(anchor), Some(period)) => Some(Heartbeat::new(anchor as u64, period as u64)),
            _ => None,
        };
        let (journal, records) = match &options.journal_path {
            Some(path) => {
                let (journal, records) = Journal::open(path)
                    .map_err(|e| napi::Error::from_reason(format!("journal {path}: {e}")))?;
                (Some(journal), records)
            }
            None => (None, Vec::new()),
        };
        let mut inner: Engine32 = if records.is_empty() {
            Messenger::new(transport, conversation, replica_keys, config, member)
        } else {
            // Resume at the barrier the schedule says it is now (or, without one, the
            // latest journalled barrier).
            let latest = records.iter().map(|(b, _, _)| *b).max().unwrap_or(0);
            let now = heartbeat
                .as_ref()
                .map(|h| h.barrier_at(now_ms()))
                .unwrap_or(latest)
                .max(latest);
            // Each record under its journalled envelope hash (a late-join record's
            // bytes no longer hash to it), all in one rebuild.
            let mut restored = Messenger::restore(
                transport,
                conversation,
                replica_keys,
                config,
                member,
                Vec::new(),
                now,
            );
            restored.import_records(records, now);
            restored
        };

        if let Some(heartbeat) = heartbeat {
            inner = inner.with_heartbeat(heartbeat);
        }
        inner = inner.with_view_checks(options.view_checks.unwrap_or(false));

        Ok(Self {
            inner,
            rng,
            authorship_vk,
            badge_vk,
            not_banned_vk,
            journal,
        })
    }

    fn emit<T>(&mut self, r: Result<Emitted, T>) -> napi::Result<JsEmitted>
    where
        T: std::fmt::Display,
    {
        let emitted = r.map_err(|e| napi::Error::from_reason(format!("emit failed: {e}")))?;
        // The messenger folded our own record into the replica: journal it.
        self.journal_record(emitted.eh, &emitted.bytes)?;
        Ok(to_emitted(emitted))
    }

    /// Journal a record the replica has seen, at its current barrier. A journal write
    /// failure is an error: a record missing from the journal would be missing after a
    /// restart, which forks this member off the group.
    fn journal_record(&mut self, eh: Eh, bytes: &[u8]) -> napi::Result<()> {
        let Some(journal) = self.journal.as_mut() else {
            return Ok(());
        };
        let Some(barrier) = self.inner.replica().first_barrier(&eh) else {
            return Ok(());
        };
        journal
            .record(eh, barrier, bytes)
            .map_err(|e| napi::Error::from_reason(format!("journal write failed: {e}")))
    }

    /// This member's private state, to save ENCRYPTED and pass back as `memberState`
    /// after a restart. Save it after every emit and before sending what was emitted:
    /// restoring a state older than a record already sent would spend a revealed
    /// nullifier again and link that record to its author. While a scan is prepared
    /// but not committed, this is the pre-scan state.
    #[napi]
    pub fn export_member_state(&self) -> napi::Result<Option<Buffer>> {
        match self.inner.export_member_state() {
            None => Ok(None),
            Some(Ok(bytes)) => Ok(Some(bytes.into())),
            Some(Err(e)) => Err(napi::Error::from_reason(format!("export failed: {e}"))),
        }
    }

    /// Whether a scan would absorb anything now: a sweep is unfinished, a callback of
    /// ours was invoked (ban, badge, settled reputation), or we near the interaction cap.
    /// When false, a scan before posting proves nothing and can be skipped.
    #[napi]
    pub fn scan_needed(&self) -> bool {
        self.inner.scan_needed()
    }

    /// Scans left to finish the sweep in progress (0 when not scanning). A sweep visits
    /// every callback, one per scan; `outstanding_callbacks` only drops when it ends.
    /// Whether this member has used its interactions: its next post must wait for a
    /// finished sweep.
    #[napi]
    pub fn scan_required(&self) -> bool {
        self.inner.scan_required()
    }

    /// Whether this member could prove now: its object is in a settled root.
    #[napi]
    pub fn is_settled(&self) -> bool {
        self.inner.is_settled()
    }

    /// Whether this member could vote or rate now, which needs less than `is_settled`.
    #[napi]
    pub fn can_prove_identity(&self) -> bool {
        self.inner.can_prove_identity()
    }

    /// Records of ours the group lost since the last call, as hex envelope hashes. The
    /// member's object is already back where it was.
    #[napi]
    pub fn take_lost(&mut self) -> Vec<String> {
        self.inner.take_lost().iter().map(ToString::to_string).collect()
    }

    /// The context a post was made in, by hex envelope hash. `None` for an unknown or
    /// anonymous post, or a context too large to be a topic's.
    #[napi]
    pub fn post_context(&self, eh: String) -> Option<f64> {
        let bytes: [u8; 32] = hex::decode(eh).ok()?.try_into().ok()?;
        let context = self
            .inner
            .replica()
            .post_context(&personas_bulletin::replica::record::Eh(bytes))?;
        (context < (1 << 53)).then_some(context as f64)
    }

    /// How many records from others name a root this replica never produced.
    #[napi]
    pub fn foreign_roots(&self) -> u32 {
        self.inner.foreign_roots() as u32
    }

    #[napi]
    pub fn sweep_remaining(&self) -> u32 {
        self.inner.sweep_remaining() as u32
    }

    /// Whether this member's current object is on the bulletin — it has joined and its
    /// records are part of this replica. After a restore, `true` means no new join.
    #[napi]
    pub fn member_on_bulletin(&self) -> bool {
        self.inner.member_on_bulletin()
    }

    /// Prove a scan without releasing it; returns its envelope hash. Check
    /// [`scan_still_valid`](Self::scan_still_valid), then [`commit_scan`] (which returns
    /// the record to send) or [`discard_scan`]. Every other emit is refused meanwhile.
    #[napi]
    pub fn prepare_scan(&mut self, dummy: bool) -> napi::Result<String> {
        self.inner
            .prepare_scan(&mut self.rng, dummy)
            .map(|eh| eh_to_hex(&eh))
            .map_err(|e| napi::Error::from_reason(format!("scan failed: {e}")))
    }

    /// Whether the prepared scan's callback roots are still this replica's current ones.
    #[napi]
    pub fn scan_still_valid(&self) -> bool {
        self.inner.scan_still_valid()
    }

    /// Release the prepared scan: fold it in and return it to send. Irrevocable.
    #[napi]
    pub fn commit_scan(&mut self) -> napi::Result<JsEmitted> {
        let committed = self.inner.commit_scan();
        self.emit(committed)
    }

    /// Abandon the prepared scan (never released) and restore the pre-scan object.
    #[napi]
    pub fn discard_scan(&mut self) -> napi::Result<()> {
        self.inner
            .discard_scan()
            .map_err(|e| napi::Error::from_reason(format!("discard failed: {e}")))
    }

    /// Prove that two of MY pseudonyms share an author. Returns the encoded proof plus
    /// its public inputs, for the caller to ship as display payload.
    ///
    /// Both pseudonyms are named by their CONTEXT — for Desktop's unlimited pseudonyms
    /// that is the nonce the UI already stores per persona. The claimed values are
    /// derived from our secret key INSIDE the circuit, so this cannot be used to assert
    /// anything about a persona we do not own.
    ///
    /// Produces no record and folds nothing: an authorship proof is a read-only
    /// statement, which is why it needed no protocol change (see
    /// PERSONAS_ZK_WORKPLAN.md step 3).
    #[napi]
    pub fn emit_authorship(&mut self, context_a: f64, context_b: f64) -> napi::Result<Buffer> {
        self.guard_not_scanning("emit_authorship")?;
        if context_a == context_b {
            // A pseudonym is trivially itself; the proof would verify and say nothing.
            return napi::Result::Err(napi::Error::from_reason(
                "emit_authorship: the two contexts are identical, which claims nothing",
            ));
        }
        let a = F::from(context_a as u64);
        let b = F::from(context_b as u64);
        self.inner
            .prove_authorship(&mut self.rng, a, b)
            .map(Buffer::from)
            .map_err(|e| napi::Error::from_reason(format!("emit_authorship failed: {e}")))
    }

    /// VERIFY an authorship proof, returning the two petnames it actually proves about
    /// — or `None` if it does not verify.
    ///
    /// The returned names are derived from the proof's OWN public inputs, never from
    /// anything the sender wrote beside it. That is the difference between a checkmark
    /// that means something and one that can be attached to someone else's persona
    /// names: a sender can hold a valid proof about two pseudonyms they really own and
    /// still display any names they like next to it. Callers must render THESE.
    #[napi]
    pub fn verify_authorship(&self, proof: Buffer) -> Option<JsAuthorship> {
        let inputs = personas_core::verify_authorship_proof(&self.authorship_vk, proof.as_ref())?;
        // Made against OUR group's tree, not one the prover built (inputs[4] is the root).
        if !self.inner.replica().has_produced_root(inputs[4]) {
            return None;
        }
        Some(JsAuthorship {
            first: personas_core::persona::petname(inputs[1]),
            second: personas_core::persona::petname(inputs[3]),
        })
    }

    /// Badge requests that have NOT been approved yet, for an admin to act on.
    ///
    /// Derived from the replica's own log rather than from any client-side list, so
    /// every admin sees the same set and an approval that has already landed disappears
    /// for everyone. Pairing works because the approval entry names its target.
    #[napi]
    pub fn pending_badge_requests(&self) -> Vec<JsBadgeRequest> {
        let log = self.inner.replica().log();

        // Targets already approved.
        let approved: std::collections::HashSet<&str> = log
            .iter()
            .filter(|e| e.kind == "BadgeApprove")
            .filter_map(|e| e.body.rsplit(" for ").next())
            .collect();

        log.iter()
            .filter(|e| e.kind == "BadgeRequest")
            .filter_map(|e| {
                let eh = eh_to_hex(&e.eh);
                if approved.contains(eh.as_str()) {
                    return None;
                }
                // Body format is ours: "requested badge slot N".
                let slot: u32 = e.body.rsplit(' ').next()?.parse().ok()?;
                Some(JsBadgeRequest { eh, slot })
            })
            .collect()
    }

    /// Request a badge: 1=Faculty, 2=Student, 3=Industry.
    ///
    /// Files a callback for an admin to approve. The badge is NOT granted here — it
    /// lands in your object only after an approval is invoked at a settlement barrier
    /// and you then scan.
    #[napi]
    pub fn emit_badge_request(&mut self, slot: u32) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_badge_request")?;
        if !(1..=3).contains(&slot) {
            return napi::Result::Err(napi::Error::from_reason(
                "emit_badge_request: slot must be 1 (Faculty), 2 (Student) or 3 (Industry)",
            ));
        }
        {
            let r = self.inner.emit_badge_request(&mut self.rng, slot as u8);
            self.emit(r)
        }
    }

    /// Approve a badge request, naming the request record's envelope hash.
    #[napi]
    pub fn emit_badge_approve(&mut self, request: String, slot: u32) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_badge_approve")?;
        if !(1..=3).contains(&slot) {
            return napi::Result::Err(napi::Error::from_reason(
                "emit_badge_approve: slot must be 1, 2 or 3",
            ));
        }
        let target = eh_from_hex(&request)?;
        {
            let r = self.inner.emit_badge_approve(target, slot as u8);
            self.emit(r)
        }
    }

    /// Prove we hold `badge` (by NAME) in its slot. Returns the encoded proof.
    #[napi]
    pub fn emit_badge_proof(&mut self, badge: String) -> napi::Result<Buffer> {
        self.guard_not_scanning("emit_badge_proof")?;
        let (slot, value) = personas_core::badge_value(&badge).ok_or_else(|| {
            napi::Error::from_reason(format!(
                "emit_badge_proof: {badge:?} is not one of Faculty, Student, Industry. \
                 Badge values are circuit constants, so no other name can be proved."
            ))
        })?;
        self.inner
            .prove_badge(&mut self.rng, F::from(slot as u64), value)
            .map(Buffer::from)
            .map_err(|e| napi::Error::from_reason(format!("emit_badge_proof failed: {e}")))
    }

    /// VERIFY a badge proof, returning the badge NAME it actually proves — or `None`.
    ///
    /// As with authorship, render what comes back from here, never a label carried in
    /// the message: otherwise a valid Student proof could be displayed as Faculty.
    #[napi]
    pub fn verify_badge_proof(&self, proof: Buffer) -> Option<String> {
        let (_slot, value, root) =
            personas_core::verify_badge_proof(&self.badge_vk, proof.as_ref())?;
        // THE ROOT CHECK. Without it a badge is forgeable: build a one-leaf tree around an
        // object whose badge slot holds the public FACULTY constant, prove against that,
        // and every recipient shows a verified badge nobody approved.
        if !self.inner.replica().has_produced_root(root) {
            return None;
        }
        // Map back through the same table the prover used, so an unrecognised value is
        // reported as unverified rather than rendered as something plausible.
        ["Faculty", "Student", "Industry"]
            .iter()
            .find(|name| personas_core::badge_value(name).map(|(_, v)| v) == Some(value))
            .map(|name| (*name).to_string())
    }

    /// Which badges does MY object actually hold? Empty for an observer, or for a
    /// member whose badge slots are all unset.
    ///
    /// Read from the member's own zk object, which is the only place a badge really
    /// exists. A badge arrives there exactly one way: an approver invokes this member's
    /// callback with `BADGE1/2/3_FLAG`, and the member's next SCAN writes it in-circuit
    /// (`standard_callback_method`). So this flips at the requester's next scan after
    /// approval, not at approval time — the same timing as a ban.
    ///
    /// This is what distinguishes a REAL badge from the decorative label the composer
    /// has been attaching: a label is a string on the wire, this is state in the object
    /// that `badge_pred` can prove.
    #[napi]
    pub fn get_badges(&self) -> Vec<String> {
        self.inner
            .member()
            .map(|m| {
                personas_core::badge_labels(
                    &m.user.data.badge1,
                    &m.user.data.badge2,
                    &m.user.data.badge3,
                )
            })
            .unwrap_or_default()
    }

    /// Am I banned? `None` for an observer with no member object.
    ///
    /// This is the member's OWN `banned` flag, read out of their zk user object. It is
    /// written by the circuit when a scan absorbs a `BAN_FLAG` callback
    /// (`personas-core/src/circuits.rs`), which is the only thing that sets it — so it
    /// flips at the banned member's next SCAN, not when the ban is cast. A banned
    /// member's post proofs then stop being satisfiable.
    ///
    /// Exposed because the effect was otherwise invisible: a banned member saw an
    /// unchanged UI and simply found that posting stopped working, with no explanation
    /// anywhere. The protocol makes a ban self-evident to its subject by design; the
    /// client has to actually surface it.
    ///
    /// Non-zero rather than `== 1`: the field is an `F`, and the circuit's own test is
    /// "is it the ban flag", so anything other than zero means banned here. Reading it
    /// as a strict equality against 1 would silently report `false` if the
    /// representation ever changed.
    #[napi]
    pub fn is_banned(&self) -> Option<bool> {
        self.inner
            .member()
            .map(|m| m.user.data.banned != F::from(0u64))
    }

    /// Is a callback sweep unfinished? While true, EVERY proving flow except another
    /// `emit_scan` will abort the process.
    ///
    /// The underlying callbacks crate ASSERTS `self.scan_index.is_none()` rather than
    /// returning an error (`callbacks/src/generic/user.rs:1465`). A failed assertion in
    /// Rust aborts, which from Electron's side is `Render process is gone ... Exit Code:
    /// 6` with no catchable JS error — the whole window dies.
    ///
    /// `personas-client` has guarded this since it was first found (`ensure_not_scanning`,
    /// FINDINGS O2). The serverless/messenger path that Desktop uses never got the same
    /// guard, so an interrupted scan left a member permanently unusable: every later
    /// action aborted the renderer on sight, which presents as "this one instance just
    /// keeps crashing" with nothing in the JS logs.
    #[napi]
    pub fn is_scanning(&self) -> bool {
        self.inner
            .member()
            .map(|m| m.user.is_scanning())
            .unwrap_or(false)
    }

    /// How many callbacks are still outstanding mid-sweep. Useful in the status panel:
    /// the remedy for a stuck scan is to keep scanning until this reaches zero.
    #[napi]
    pub fn outstanding_callbacks(&self) -> u32 {
        self.inner
            .member()
            .map(|m| m.user.num_outstanding_callbacks() as u32)
            .unwrap_or(0)
    }

    /// Refuse a proving flow that would hit the assertion above, with an error the JS
    /// side can catch and show. `emit_scan` is deliberately exempt: continuing the scan
    /// is the only way OUT of this state.
    fn guard_not_scanning(&self, what: &str) -> napi::Result<()> {
        if self.is_scanning() {
            return napi::Result::Err(napi::Error::from_reason(format!(
                "{what} refused: a callback scan is unfinished ({} outstanding). \
                 Scan until it completes first — proceeding would abort the process.",
                self.outstanding_callbacks()
            )));
        }
        Ok(())
    }

    /// This replica's history for a member who joined LATE, with the text of past
    /// posts and polls removed (they need the group's state, not its old messages).
    /// A Signal group admin sends it; the newcomer passes it to `import_catch_up`.
    #[napi]
    pub fn export_catch_up(&self) -> Buffer {
        let records = self.inner.catch_up_records();
        let mut out = Vec::new();
        out.extend_from_slice(CATCH_UP_MAGIC);
        out.extend_from_slice(&self.inner.replica().current_barrier().to_le_bytes());
        for (barrier, eh, bytes) in records {
            out.extend_from_slice(&barrier.to_le_bytes());
            out.extend_from_slice(&eh.0);
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        Buffer::from(out)
    }

    /// Take in a history from `export_catch_up`, TRUSTING whoever sent it (the client
    /// accepts one only from a group admin): the records are verified as usual, but
    /// nothing checks that the set is complete or that the hashes are genuine. Journalled
    /// so it survives a restart. Returns how many records were new.
    #[napi]
    pub fn import_catch_up(&mut self, history: Buffer) -> napi::Result<u32> {
        let raw = history.as_ref();
        let bad = || napi::Error::from_reason("not a personas catch-up history");
        if raw.len() < 12 || &raw[..4] != CATCH_UP_MAGIC {
            return Err(bad());
        }
        let at = u64::from_le_bytes(raw[4..12].try_into().expect("8 bytes"));
        let mut items = Vec::new();
        let mut pos = 12;
        while pos < raw.len() {
            let head = raw.get(pos..pos + 44).ok_or_else(bad)?;
            let barrier = u64::from_le_bytes(head[..8].try_into().expect("8 bytes"));
            let eh = Eh(head[8..40].try_into().expect("32 bytes"));
            let len = u32::from_le_bytes(head[40..44].try_into().expect("4 bytes")) as usize;
            let bytes = raw.get(pos + 44..pos + 44 + len).ok_or_else(bad)?;
            items.push((barrier, eh, bytes.to_vec()));
            pos += 44 + len;
        }
        let ehs: Vec<Eh> = items.iter().map(|(_, eh, _)| *eh).collect();
        let added = self.inner.import_records(items, at);
        for eh in ehs {
            let Some(bytes) = self.inner.replica().seen_bytes(&eh).map(<[u8]>::to_vec) else {
                continue;
            };
            self.journal_record(eh, &bytes)?;
        }
        Ok(added as u32)
    }

    /// Emit a join record (a member advertising itself to the group).
    #[napi]
    pub fn emit_join(&mut self, account: String) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_join")?;
        let account = account_from_hex(&account)?;
        let r = self.inner.emit_join(&mut self.rng, account);
        self.emit(r)
    }

    /// As a group admin, allow `account` (32 hex chars: the ACI without dashes) one more
    /// join. Send it under the admin's OWN account: members only ingest it from an admin.
    #[napi]
    pub fn emit_rejoin_approve(
        &mut self,
        account: String,
        proof: Option<Buffer>,
    ) -> napi::Result<JsEmitted> {
        let account = account_from_hex(&account)?;
        let r = self
            .inner
            .emit_rejoin_approve(account, proof.as_ref().map(|p| p.as_ref()));
        self.emit(r)
    }

    /// As a group admin: ban the author of post `target` (its eh, hex) permanently and
    /// at once — no poll. Send it under the admin's OWN account: members only ingest it
    /// from an admin.
    #[napi]
    pub fn emit_ban(&mut self, target: String) -> napi::Result<JsEmitted> {
        let target = eh_from_hex(&target)?;
        let r = self.inner.emit_ban(target);
        self.emit(r)
    }

    /// The proof a reset request carries: this member, as `account`, is not banned and
    /// has just completed a scan sweep, against the group's current tree. Fails when the
    /// member is banned, has not swept since its last action, or is out of sync.
    #[napi]
    pub fn prove_not_banned(&mut self, account: String) -> napi::Result<Buffer> {
        self.guard_not_scanning("prove_not_banned")?;
        let account = account_from_hex(&account)?;
        self.inner
            .prove_not_banned(&mut self.rng, account)
            .map(Buffer::from)
            .map_err(|e| napi::Error::from_reason(format!("prove_not_banned failed: {e}")))
    }

    /// Check a reset request's proof. Returns the account (hex) it proves for, only if
    /// the proof verifies AND was made against a tree this replica produced — otherwise
    /// it is a statement about a tree the requester built.
    #[napi]
    pub fn verify_not_banned(&self, proof: Buffer) -> Option<String> {
        let (account, _nul, root) =
            personas_core::verify_not_banned_proof(&self.not_banned_vk, proof.as_ref())?;
        if !self.inner.replica().has_produced_root(root) {
            return None;
        }
        Some(hex::encode(personas_core::account_bytes(&account)))
    }

    /// Start over with a fresh object under the same secret key — after an admin approved
    /// this account's re-join. Badges and reputation are abandoned; pseudonyms stay.
    #[napi]
    pub fn reset_member(&mut self) -> napi::Result<()> {
        self.inner
            .reset_member(&mut self.rng)
            .map_err(|e| napi::Error::from_reason(format!("reset_member failed: {e}")))
    }

    /// Joins applied and re-joins approved for `account`. It may join while
    /// `joins < 1 + approved`.
    #[napi]
    pub fn join_counts(&self, account: String) -> napi::Result<JsJoinCounts> {
        let (joins, approved) = self
            .inner
            .replica()
            .join_counts(account_from_hex(&account)?);
        Ok(JsJoinCounts { joins, approved })
    }

    /// For records whose sender the client must check before ingesting: a JOIN (the
    /// account must be the sender) or a RE-JOIN APPROVAL (the sender must be a group
    /// admin). `None` for any other record.
    #[napi]
    pub fn record_account_claim(&self, record: Buffer) -> Option<JsAccountClaim> {
        let (rec, _) = personas_bulletin::replica::record::decode(record.as_ref()).ok()?;
        let (kind, account) = match rec {
            personas_bulletin::replica::record::Record::Join { account, .. } => ("join", account.0),
            personas_bulletin::replica::record::Record::RejoinApprove { account, .. } => {
                ("rejoin-approve", account.0)
            }
            // These name no account, but like a re-join approval they must come from an
            // admin.
            personas_bulletin::replica::record::Record::Ban { .. } => {
                return Some(JsAccountClaim {
                    kind: "ban".to_string(),
                    account: String::new(),
                });
            }
            personas_bulletin::replica::record::Record::BadgeApprove { .. } => {
                return Some(JsAccountClaim {
                    kind: "badge-approve".to_string(),
                    account: String::new(),
                });
            }
            _ => return None,
        };
        Some(JsAccountClaim {
            kind: kind.to_string(),
            account: hex::encode(personas_core::account_bytes(&account)),
        })
    }

    /// The text and kind of a `PollOpen` record, read from its bytes; `None` for any other
    /// record. What a poll bubble is drawn from, so a poll cannot display one thing and
    /// mean another.
    #[napi]
    pub fn record_poll(&self, record: Buffer) -> Option<JsPollText> {
        use personas_bulletin::replica::record::Record;
        let (rec, _) = personas_bulletin::replica::record::decode(record.as_ref()).ok()?;
        let Record::PollOpen {
            question,
            options,
            kind,
            ..
        } = rec
        else {
            return None;
        };
        Some(JsPollText {
            question,
            options,
            kind: match kind {
                PollKind::Ban => "ban",
                PollKind::Standard => "standard",
            }
            .to_string(),
        })
    }

    /// What kind of record `record` is ("Post", "Join", "Vote", ...), read from its bytes
    /// alone: nothing is verified or applied. For a record the replica is holding
    /// (`buffered`), so the timeline can keep a place for a post that applies later.
    #[napi]
    pub fn record_kind(&self, record: Buffer) -> Option<String> {
        let (rec, _) = personas_bulletin::replica::record::decode(record.as_ref()).ok()?;
        Some(rec.kind().to_string())
    }

    /// Emit a pseudonymous post under `context` (the thread/topic the persona is
    /// scoped to). Generates a real Groth16 proof — seconds at production heights.
    #[napi]
    pub fn emit_post_pseudo(&mut self, body: String, context: f64) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_post_pseudo")?;
        let ctx = F::from(context as u64);
        {
            let r = self.inner.emit_post_pseudo(&mut self.rng, body, ctx);
            self.emit(r)
        }
    }

    /// Emit an anonymous post (no linkable persona).
    #[napi]
    pub fn emit_post_anon(&mut self, body: String) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_post_anon")?;
        {
            let r = self.inner.emit_post_anon(&mut self.rng, body);
            self.emit(r)
        }
    }

    /// Emit a rate-limited pseudonymous post as the `i`-th persona for `context`.
    /// Different `i` values yield different persona petnames under the same context,
    /// which is how the composer's pseudonym picker offers distinct personas.
    #[napi]
    pub fn emit_post_pseudo_rate(
        &mut self,
        body: String,
        context: f64,
        i: f64,
    ) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_post_pseudo_rate")?;
        let ctx = F::from(context as u64);
        let idx = F::from(i as u64);
        let r = self
            .inner
            .emit_post_pseudo_rate(&mut self.rng, body, ctx, idx);
        self.emit(r)
    }

    /// Open a poll. `kind` is `"ban"` or `"standard"`; `target` (hex `Eh`) is the
    /// post under review for a ban poll.
    #[napi]
    pub fn emit_poll(
        &mut self,
        question: String,
        options: Vec<String>,
        kind: String,
        target: Option<String>,
    ) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_poll")?;
        let poll_kind = match kind.as_str() {
            "ban" => PollKind::Ban,
            "standard" => PollKind::Standard,
            other => {
                return Err(napi::Error::from_reason(format!(
                    "unknown poll kind: {other}"
                )));
            }
        };
        let target_eh = match target {
            Some(s) => Some(eh_from_hex(&s)?),
            None => None,
        };
        {
            let r = self
                .inner
                .emit_poll(question, options, poll_kind, target_eh);
            self.emit(r)
        }
    }

    /// Cast a ballot (`option` index) in the poll named by hex `Eh` `poll`.
    #[napi]
    pub fn emit_vote(&mut self, poll: String, option: u32) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_vote")?;
        let poll_eh = eh_from_hex(&poll)?;
        {
            let r = self.inner.emit_vote(&mut self.rng, poll_eh, option);
            self.emit(r)
        }
    }

    /// Rate the record named by hex `Eh` `target` by `delta` (§10).
    #[napi]
    pub fn emit_rate(&mut self, target: String, delta: i32) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_rate")?;
        let target_eh = eh_from_hex(&target)?;
        {
            let r = self.inner.emit_rate(&mut self.rng, target_eh, delta as i8);
            self.emit(r)
        }
    }

    /// Emit a scan absorbing every callback invoked on this member since its last
    /// scan (§5.2) — how a banned member's ban becomes self-evident.
    #[napi]
    pub fn emit_scan(&mut self) -> napi::Result<JsEmitted> {
        {
            let r = self.inner.emit_scan(&mut self.rng);
            self.emit(r)
        }
    }

    /// Ingest a record that arrived over Desktop. `received_at_ms` is the service
    /// receive timestamp used to bucket the record onto the shared barrier schedule;
    /// pass `0` to fall back to the local barrier (the manual-cadence path).
    #[napi]
    pub fn ingest(&mut self, record: Buffer, received_at_ms: f64) -> napi::Result<JsStatus> {
        // The record's envelope hash, so the caller can find the resulting chat-log
        // entry (a post) after a successful ingest.
        let decoded_eh = personas_bulletin::replica::record::decode(record.as_ref())
            .ok()
            .map(|(_, eh)| eh);
        let eh = decoded_eh.as_ref().map(eh_to_hex).unwrap_or_default();
        let carried = carriage::encode(record.as_ref());
        let incoming = Incoming::Message {
            id: MessageId("desktop".into()),
            conversation: self.inner.conversation().clone(),
            sender: "peer".into(),
            body: carried.body,
            reply_to: None,
            attachments: carried.attachment.into_iter().collect(),
            received_at: received_at_ms as u64,
        };
        let result = self.inner.ingest_incoming(&incoming);
        if let (Some(Ok(_)), Some(decoded)) = (&result, decoded_eh) {
            self.journal_record(decoded, record.as_ref())?;
        }
        match result {
            None => Err(napi::Error::from_reason(
                "ingest: body carried no record (marker missing)",
            )),
            Some(Err(e)) => Err(napi::Error::from_reason(format!("ingest decode: {e}"))),
            Some(Ok(status)) => Ok(js_status(status, eh)),
        }
    }

    /// Ingest a record another member RELAYED because views disagreed (§5.5), at the
    /// `barrier` the relay names. `received_at_ms` is the relay message's own service
    /// timestamp; the record is never placed after it. A record we already hold is
    /// left where it is.
    #[napi]
    pub fn ingest_relayed(
        &mut self,
        record: Buffer,
        barrier: f64,
        received_at_ms: f64,
    ) -> napi::Result<JsStatus> {
        let bytes = record.to_vec();
        let decoded = personas_bulletin::replica::record::decode(&bytes)
            .map_err(|e| napi::Error::from_reason(format!("ingest decode: {e}")))?
            .1;
        let status = self
            .inner
            .ingest_relayed(bytes.clone(), barrier as u64, received_at_ms as u64)
            .map_err(|e| napi::Error::from_reason(format!("ingest decode: {e}")))?;
        self.journal_record(decoded, &bytes)?;
        Ok(js_status(status, eh_to_hex(&decoded)))
    }

    /// Whether the records we have received carry views of the group that match ours.
    /// Check after each ingest; when `diverged`, tell the user that the messenger may
    /// be showing members different messages.
    #[napi]
    pub fn view_report(&self) -> JsViewReport {
        let report = self.inner.view_report();
        JsViewReport {
            diverged: report.diverged(),
            agreeing: report.agreeing,
            pending: report.pending,
            mismatches: report
                .mismatches
                .iter()
                .map(|m| JsViewMismatch {
                    barrier: m.barrier as f64,
                    eh: eh_to_hex(&m.record),
                })
                .collect(),
        }
    }

    /// The records to relay to the group because views disagree, each returned once.
    /// Call after each ingest and send every one with its barrier.
    #[napi]
    pub fn take_relays(&mut self) -> Vec<JsRelay> {
        self.inner
            .take_relays()
            .into_iter()
            .map(|(barrier, record)| JsRelay {
                barrier: barrier as f64,
                record: record.into(),
            })
            .collect()
    }

    /// The accepted chat log as display lines (`~petname: msg`, flagged where a
    /// persona was later revoked).
    #[napi]
    pub fn render(&self) -> Vec<String> {
        self.inner.render()
    }

    /// The open and recently-closed polls as status lines.
    #[napi]
    pub fn render_polls(&self) -> Vec<String> {
        self.inner.render_polls()
    }

    /// The accepted log as structured entries for the UI.
    #[napi]
    pub fn log(&self) -> Vec<JsLogEntry> {
        self.inner
            .replica()
            .log()
            .iter()
            .map(|e| JsLogEntry {
                eh: eh_to_hex(&e.eh),
                kind: e.kind.to_string(),
                author: e.author.clone(),
                body: e.body.clone(),
                flagged: e.flagged,
            })
            .collect()
    }

    /// The chat-log entry for a given envelope hash (hex), or `None` if that record
    /// is not a rendered post (joins/votes/polls carry no log entry) or is unknown.
    #[napi]
    pub fn log_entry(&self, eh: String) -> Option<JsLogEntry> {
        let target = eh_from_hex(&eh).ok()?;
        self.inner
            .replica()
            .log()
            .iter()
            .find(|e| e.eh == target)
            .map(|e| JsLogEntry {
                eh: eh_to_hex(&e.eh),
                kind: e.kind.to_string(),
                author: e.author.clone(),
                body: e.body.clone(),
                flagged: e.flagged,
            })
    }

    /// Cross exactly one settlement barrier by hand (settle due tickets, close ban
    /// polls, re-pin the callback root). The manual-cadence counterpart of [`tick`].
    #[napi]
    pub fn barrier(&mut self) {
        self.inner.barrier();
    }

    /// Advance to the barrier the shared schedule says `now_ms` has reached; returns
    /// the barrier the replica is now at.
    #[napi]
    pub fn tick(&mut self, now_ms: f64) -> f64 {
        self.inner.tick(now_ms as u64) as f64
    }

    /// A convergence fingerprint: the three replica roots (object, callback
    /// membership, callback non-membership) as concatenated hex. Two engines that
    /// have ingested the same records across the same barriers share it exactly.
    #[napi]
    pub fn fingerprint(&self) -> String {
        self.fingerprint_inner()
    }

    /// EXPERIMENTS: how long the last operation (an emit, a scan, or a proof) took.
    #[napi]
    pub fn last_op_timings(&self) -> JsOpTimings {
        let t = self.inner.last_op_timings();
        JsOpTimings {
            prove_ms: t.prove_us as f64 / 1000.0,
            self_ingest_ms: t.self_ingest_us as f64 / 1000.0,
            bytes: u32::try_from(t.bytes).unwrap_or(u32::MAX),
        }
    }

    /// EXPERIMENTS: the latest barrier at which callbacks were invoked, with its cost.
    #[napi]
    pub fn last_settle_timings(&self) -> Option<JsSettleTimings> {
        let (barrier, t) = self.inner.replica().last_settle_timings()?;
        Some(JsSettleTimings {
            barrier: barrier as f64,
            invoked: t.invoked,
            invoke_ms: t.invoke_us as f64 / 1000.0,
            epoch_update_ms: t.epoch_update_us as f64 / 1000.0,
        })
    }

    fn fingerprint_inner(&self) -> String {
        let r = self.inner.replica();
        format!(
            "{}:{}:{}",
            root_hex(&r.obj_root()),
            root_hex(&r.cb_memb_root()),
            root_hex(&r.cb_nmemb_root())
        )
    }

    /// The barrier this replica is currently at.
    #[napi]
    pub fn current_barrier(&self) -> f64 {
        self.inner.replica().current_barrier() as f64
    }

    // ==================================================================
    // BISECT STAGE 1 of 4 — see PERSONAS_ZK_WORKPLAN.md step 2.
    //
    // An earlier `get_reputation` compiled cleanly and then SIGKILLed the Electron
    // render process (exit code 9, no catchable error). Rebuilding from unmodified
    // upstream Rust is stable, so the fault is somewhere in that ~15-line change —
    // but it was never narrowed, and authorship (~60 lines) and badges (several
    // hundred) are the same shape. So before building either, find out which LAYER
    // breaks, by adding one capability at a time:
    //
    //   STAGE 1 (this)  two methods that touch no data at all.
    //                   Crash  => adding ANY napi method to this crate breaks the
    //                             addon. Nothing else should be attempted. Suspect
    //                             napi-derive/codegen, the Electron ABI, or the
    //                             build itself.
    //                   Stable => napi codegen and f64/Option marshalling are fine.
    //                             Go to stage 2.
    //
    //   STAGE 2  `self.inner.member().map(|_| 0.0)`  — borrowing the Member.
    //            Crash => the fault is in reaching into `inner`, not in arithmetic.
    //
    //   STAGE 3  return a hardcoded field element through the real conversion, e.g.
    //            `field_to_f64(&F::from(7u64))` — the arithmetic alone.
    //            Crash => `field_to_f64` is the culprit (it was my code: it does
    //            `into_bigint().to_bytes_le()` and a negation `-*value`).
    //
    //   STAGE 4  the real thing: `member().map(|m| field_to_f64(&m.user.data.reputation))`.
    //            Crash here, with 1-3 stable, means the specific field access is at
    //            fault.
    //
    // Rebuild and run between EVERY stage. One variable at a time is the only thing
    // that has produced a reliable answer on this bug so far.
    //
    // Capture the kill reason while it reproduces — this was never obtained:
    //   log stream --predicate 'eventMessage CONTAINS "Signal"' --info
    //
    // DELETE this whole block once the answer is known.

    /// Bisect probe: the simplest possible added method. Returns a constant.
    #[napi]
    pub fn bisect_ping(&self) -> f64 {
        1.0
    }

    /// This member's own reputation, or `None` for an observer (no member) — the UI
    /// renders that as "—".
    ///
    /// Reputation is a member's OWN state: it lives in their zk user object, which is
    /// why nobody can look up anyone else's. It moves when a `Rate` callback is absorbed
    /// by a scan (`personas-core/src/circuits.rs`, `u.data.reputation += argument`), NOT
    /// when the rating is sent. So the sequence that changes this value is
    /// rate -> scan, and a scan with no outstanding callbacks correctly changes nothing.
    ///
    /// This replaces a bisect stub that returned a constant `Some(0.0)`. The stub was
    /// indistinguishable from a working implementation on a fresh member — both read
    /// zero — so the status panel showed a plausible 0 that never moved, for either
    /// reason. That is the kind of "working" display this panel exists to avoid.
    /// RESOLVED: the exit-9 crash was NOT in this function.
    ///
    /// Adding `ark-ff` as a direct dependency of this crate (to get `PrimeField`) made
    /// the built `.node` kill the Electron renderer at LOAD — before `background.html`
    /// rendered and long before any method here ran. A stage-1 build, whose body was the
    /// byte-identical `Some(0.0)` stub that had always been stable, crashed the same way.
    /// That isolated it to the dependency graph: one new edge in `Cargo.lock` changed
    /// Cargo's feature unification and produced an addon that would not initialise.
    ///
    /// The conversion therefore lives in `personas-core`, which already depends on
    /// `ark-ff`, leaving this crate's dependency graph identical to the known-good one.
    /// With that change the real read below runs fine.
    ///
    /// Worth keeping, because it answers a question that blocked all Rust work on this
    /// project for weeks: exit 9 here was a BUILD problem, not a sign that this layer
    /// cannot be extended. Authorship and badges are the same shape and are not
    /// inherently unsafe to attempt — just do not add dependencies to this crate.
    ///
    /// `PERSONAS_REPUTATION_STAGE` is retained for a future bisect of the same kind:
    ///   1  constant, no data access        3  convert a hardcoded field
    ///   2  borrow the Member, ignore it    4  the real read (DEFAULT)
    #[napi]
    pub fn get_reputation(&self) -> Option<f64> {
        let stage = std::env::var("PERSONAS_REPUTATION_STAGE")
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(4);

        match stage {
            1 => Some(0.0),
            2 => self.inner.member().map(|_| 0.0),
            3 => Some(personas_core::field_to_f64_signed(&F::from(7u64))),
            // The real read. `None` for an observer with no member — the UI shows "—".
            _ => self
                .inner
                .member()
                .map(|m| personas_core::field_to_f64_signed(&m.user.data.reputation)),
        }
    }
}

/// Wall-clock milliseconds since the Unix epoch, for placing a restored replica on the
/// shared barrier schedule.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn js_status(status: Status, eh: String) -> JsStatus {
    let (status, reason) = match status {
        Status::Applied => ("applied", None),
        Status::Buffered => ("buffered", None),
        Status::Rejected(reason) => ("rejected", Some(reason.to_string())),
    };
    JsStatus {
        status: status.into(),
        reason,
        eh,
    }
}
