//! The serverless record model and its byte codec (workstream **d3**).
//!
//! In *service* mode a record's type is the HTTP route it arrived on, and its
//! payload is whatever that route's handler expects — an `ExecutedMethod`, then
//! maybe a `Vec<F>` of public inputs, with the message body travelling *beside*
//! the proof in the JSON request. Serverless deletes the routes: a record is a
//! chat message, and the reader has to work out what it is, and reconstruct
//! everything the server used to supply, from the bytes alone. So the body moves
//! *into* the record, and every record names the object root it was built on —
//! the two changes `SERVERLESS_PROTOCOL.md` §3 calls the wire break to version 2.
//!
//! This module is that wire, kept deliberately self-contained rather than folded
//! into [`personas_wire`]: the service server still speaks `personas_wire`
//! version 1, and the serverless record set (new kinds `Rate`/`PollOpen`/`Vote`,
//! new fields `body`/`obj_root`) is only meaningful to the replica engine. When
//! records actually ride Signal (workstream e2) this is where `personas_wire`
//! version 2 gets reconciled.
//!
//! # Shape
//!
//! A [`Record`] is a plain `serde` enum. The arkworks values inside it —
//! `ExecutedMethod`, Groth16 proofs, field elements — are not `serde` types, so
//! each is wrapped in [`Ark`], which serialises through arkworks'
//! `CanonicalSerialize` into a CBOR byte string. The whole thing is CBOR-encoded
//! into an [`Envelope`] carrying a version, and the record is referenced
//! everywhere by its **envelope hash** ([`Eh`]) — the collision-resistant hash of
//! those envelope bytes, never a messenger id (§4: ids are sender-set and
//! non-unique, so any cross-reference keyed on one is forgeable).

use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use blake2::{Blake2s256, Digest};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zk_callbacks::generic::object::{Com, Nul};
use zk_callbacks::generic::user::ExecutedMethod;

use personas_core::{Args, Cr, F, Snark};

/// The serverless protocol version. Distinct from [`personas_wire::VERSION`] (1):
/// a reader that sees a version it does not know refuses the record rather than
/// misread a version-1 service payload as a version-2 serverless one.
///
/// 3: a join carries the joining account and a proof that its object is fresh, and a
/// group admin's re-join approval exists. A version-2 record is refused.
///
/// 4: proofs bind their payload, a join carries the member's public key, a re-join
/// approval can spend the object given up, and a record's identity no longer depends on
/// its proof bytes or view claim.
pub const SERVERLESS_VERSION: u16 = 4;

/// Records are compressed, matching `personas_wire`'s reasoning: every member
/// downloads every record forever, so halving a proof is worth the point
/// decompressions it costs to read.
const COMPRESS: Compress = Compress::Yes;

/// A member's committed post carries exactly one callback ticket (`NUMCBS = 1`);
/// a scan carries none (`NUMCBS = 0`). Named here so the codec and the engine
/// agree.
pub type PostExec = ExecutedMethod<F, Snark, Args, Cr, 1>;
/// A scan's `ExecutedMethod`: it invokes no new callbacks, so `NUMCBS = 0`.
pub type ScanExec = ExecutedMethod<F, Snark, Args, Cr, 0>;
/// A standalone Groth16 proof (a vote or a rating).
pub type PredProof = <Snark as ark_snark::SNARK<F>>::Proof;

// ---------------------------------------------------------------------------------------
// Eh — the envelope hash
// ---------------------------------------------------------------------------------------

/// A record's identity: the collision-resistant hash of what it states.
///
/// Every cross-reference in the protocol — a rating's target, a vote's poll, an
/// admin ban's post — names an `Eh`, so it must not change when a record is re-encoded.
/// A Groth16 proof can be re-randomized by anyone and a view claim is outside every proof,
/// so neither is part of it (see [`identity`]). It is a byte digest (so it
/// is `Hash`/`Eq` and keys a map cleanly); the field-element a circuit needs (a
/// poll or rating **context**) is derived from it by [`Eh::context`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Eh(pub [u8; 32]);

impl Eh {
    /// The digest of some bytes. A record's own `Eh` comes from [`identity`].
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut h = Blake2s256::new();
        h.update(bytes);
        Eh(h.finalize().into())
    }

    /// The field-element **context** a pseudonym is derived against for this
    /// record: `H(eh)` (`SERVERLESS_PROTOCOL.md` §8 for polls, §10 for ratings).
    ///
    /// Deterministic (every replica computes the same one), unpredictable before
    /// the record exists (which is what stops a member pre-computing a pseudonym),
    /// and unique per record (which keeps pseudonyms in different polls/targets
    /// unlinkable). It replaces the service's `fresh_context()`.
    pub fn context(&self) -> F {
        crate::merkle::tree::poseidon2(&[F::from_le_bytes_mod_order(&self.0)])
    }
}

impl std::fmt::Debug for Eh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Eh({})", hex::encode(&self.0[..6]))
    }
}

impl std::fmt::Display for Eh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ---------------------------------------------------------------------------------------
// Ark<T> — an arkworks value inside a serde document
// ---------------------------------------------------------------------------------------

/// A `CanonicalSerialize` value carried inside a `serde` structure as a CBOR byte
/// string.
///
/// arkworks and serde are two different serialisation worlds; a `Record` needs
/// both (a `serde` enum whose variants hold `ExecutedMethod`s and field
/// elements). Rather than hand-roll every variant, one wrapper bridges them:
/// `serialize` writes the arkworks bytes into `serde_bytes`, `deserialize` reads
/// them back with `Validate::Yes` — a record is adversarial input, so its curve
/// points are checked to be on-curve and in-subgroup before a proof ever touches
/// them.
#[derive(Clone)]
pub struct Ark<T>(pub T);

impl<T> std::fmt::Debug for Ark<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The inner arkworks value is not `Debug`; its identity is its bytes, which
        // the record's `Eh` already captures, so a placeholder is all that is useful.
        f.write_str("Ark(..)")
    }
}

impl<T: CanonicalSerialize> Serialize for Ark<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        self.0
            .serialize_with_mode(&mut bytes, COMPRESS)
            .map_err(serde::ser::Error::custom)?;
        serde_bytes::serialize(&bytes, s)
    }
}

impl<'de, T: CanonicalDeserialize> Deserialize<'de> for Ark<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = serde_bytes::deserialize(d)?;
        let value = T::deserialize_with_mode(&bytes[..], COMPRESS, Validate::Yes)
            .map_err(D::Error::custom)?;
        Ok(Ark(value))
    }
}

// ---------------------------------------------------------------------------------------
// The record kinds
// ---------------------------------------------------------------------------------------

/// What a post claims about its author — the serverless mirror of the service
/// `Flavour`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flavour {
    /// Nothing: an unlinkable post by some unbanned member.
    Anon,
    /// A pseudonym, scoped to a member-chosen context.
    Pseudo,
    /// A pseudonym plus an index `i`, holding a member to `RATE_LIMITED_PERSONAS_PER_CONTEXT` (3) pseudonyms
    /// per context.
    PseudoRate,
}

/// Whether a poll merely gauges opinion or, if it carries and passes, revokes a
/// post's author.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PollKind {
    /// An ordinary poll: the tally is rendered, nothing is invoked.
    Standard,
    /// A ban poll: if it closes `yes > no`, the target's ticket is settled with
    /// `BAN_FLAG` at the close barrier (§7).
    Ban,
}

/// The object a member gives up by re-joining: its `not_banned_pred` proof and the
/// nullifier and root that proof is about.
#[derive(Debug, Serialize, Deserialize)]
pub struct SpentObject {
    pub nul: Ark<Nul<F>>,
    pub root: Ark<F>,
    pub proof: Ark<PredProof>,
}

/// A serverless record: one accept-rule input, self-describing from its bytes.
///
/// Every proof-carrying variant names the `obj_root` it was built on, because the
/// verifier has to know which root to pin before it can verify (§5.1) — a member
/// proves against whatever recent root they hold, and the replica accepts only a
/// root it computed itself.
///
/// Not `Clone`: an `ExecutedMethod` holds a Groth16 proof that is neither `Clone`
/// nor `Debug`, and a record is a use-once ingest input anyway. The engine buffers
/// and journals records as *bytes*, never as owned `Record`s.
#[derive(Debug, Serialize, Deserialize)]
pub enum Record {
    /// A member joining: a commitment to their fresh object, plus the initial
    /// nullifier that object consumes. Unlike the service store (which samples the
    /// nullifier randomly on join), serverless carries it as data so every replica
    /// appends an identical leaf — determinism is a hard requirement (§d1).
    ///
    /// PROVEN (version 3): `proof` is a `join_pred` proof with public inputs
    /// `[object, account]` — the committed object is fresh (no badges, reputation, ban
    /// flag, callbacks or scan state; only its secret key and randomness are its own) —
    /// so a member can no longer join with an object of its own making. `account` is the
    /// joining Signal account (`personas_core::account_field` of its ACI); the replica
    /// allows one join per account plus one per admin re-join approval, and the client
    /// refuses a join whose `account` is not the account that sent it.
    ///
    /// `pk` is the member's public key, proved to be a hash of its `sk`. The replica ties
    /// each `pk` to one account, so two accounts cannot share an `sk` (and so a ban on one
    /// cannot miss the other), and a re-join must use the account's original `pk`.
    Join {
        object: Ark<Com<F>>,
        old_nul: Ark<Nul<F>>,
        account: Ark<F>,
        pk: Ark<F>,
        proof: Ark<PredProof>,
    },

    /// A group admin allows `account` ONE more join (after a reset request). Carries no
    /// proof; the client accepts it only when its sender is a Signal group admin, and
    /// it is sent under the admin's own account so every member can check that.
    ///
    /// `spent` carries the requester's `not_banned_pred` proof when it has one, and
    /// approving spends that object. It is `None` only for a member whose object fell off
    /// the bulletin, which an admin has to take on trust.
    RejoinApprove {
        account: Ark<F>,
        spent: Option<SpentObject>,
    },

    /// A post. `extra` is the flavour's public arguments: empty for `Anon`,
    /// `[context, claimed]` for `Pseudo`, `[context, claimed, i]` for
    /// `PseudoRate`. The context of a plain pseudonym is member-chosen (not a
    /// replica-derived one), so it rides in the proof's public inputs and the
    /// replica pins only `obj_root`.
    ///
    /// `payload` is [`post_payload`] of `body`, a public input of the proof, so the text
    /// cannot be changed under the proof. It is its own field because a late joiner gets
    /// the record with `body` removed and must still verify the proof.
    Post {
        flavour: Flavour,
        exec: Ark<PostExec>,
        extra: Ark<Vec<F>>,
        body: String,
        payload: Ark<F>,
        obj_root: Ark<F>,
    },

    /// A BADGE REQUEST. An interaction, like a post, so it files a callback — and that
    /// callback is the thing an approver later invokes with a BADGE flag. Without a
    /// ticket there would be nothing to approve.
    ///
    /// CARRIES NO IDENTITY, and does not need to. The grant travels by callback: the
    /// approval names this record's envelope hash, the replica marks the ticket, and the
    /// requester absorbs it at their next scan because only they can. So who sent this
    /// record is irrelevant to whether the badge lands, and the Desktop client
    /// accordingly carries it under the anonymous phantom identity (`PZB2:` in
    /// personasCarriage.std.ts) rather than the real account.
    ///
    /// An earlier version of this comment claimed the request was "attributable by
    /// design" because a human admin must vouch for a person. That describes a different
    /// protocol than the one implemented here — nothing below reads a requester identity.
    /// The consequence is that an admin approves a REQUEST, not a PERSON.
    ///
    /// `slot` is which badge is being asked for (1=Faculty, 2=Student, 3=Industry). It
    /// is DATA, not proof: the request says what you want, the approval decides whether
    /// you get it, and the circuit decides what the flag means.
    BadgeRequest {
        exec: Ark<PostExec>,
        slot: u8,
        obj_root: Ark<F>,
    },

    /// An approval of a badge request, naming the request's envelope hash.
    ///
    /// Carries no proof. Like the request, it is carried anonymously (under the phantom
    /// identity) by the Desktop client: an approval that named its sender while the
    /// request did not would narrow the request's anonymity set to "whoever that admin
    /// replied to", so the pair has to agree. The accept rule only marks the requester's
    /// ticket, and the existing barrier machinery does the rest: invoke with the BADGE
    /// flag, then the requester's own scan writes the badge in-circuit.
    ///
    /// NOT AUTHENTICATED. Desktop shows the Approve button only to group admins, but
    /// because the approval rides the phantom, no receiver can check who sent it, and
    /// nothing in this accept rule does either: a modified client can approve its own
    /// request. Closing that needs an authority key in the group config and a signature
    /// checked here (`SERVERLESS_PROTOCOL.md` §11).
    BadgeApprove { target: Eh, slot: u8 },

    /// A rating of another record. Serverless erases the reacting account, so a
    /// rating must now carry a proof (§10): `pseudonym_pred` under
    /// `context = target.context()`, revealing `claimed`. One rating per
    /// `claimed` per target.
    Rate {
        target: Eh,
        delta: i8,
        proof: Ark<PredProof>,
        claimed: Ark<F>,
        obj_root: Ark<F>,
    },

    /// Announce a poll. Its context is not minted by anyone — it is
    /// `this_record.context()` (§8), so voters can derive their poll pseudonym
    /// only once the poll exists.
    PollOpen {
        question: String,
        options: Vec<String>,
        kind: PollKind,
        /// The post under review, for a `Ban` poll.
        target: Option<Eh>,
    },

    /// A ballot in a poll. Proves `pseudonym_pred` under the poll's context; the
    /// replica records it against `claimed` (one member, one vote) and a later
    /// ballot from the same `claimed` replaces the earlier one.
    Vote {
        poll: Eh,
        option: u32,
        proof: Ark<PredProof>,
        claimed: Ark<F>,
        obj_root: Ark<F>,
    },

    /// A callback scan: the member proves they absorbed every callback invoked on
    /// them since their last scan and skipped none. `cb_memb_root`/`cb_nmemb_root`
    /// name the barrier the scan proves against; the replica pins its *own*
    /// current-barrier roots (§5.2) and rejects a scan built on a superseded one.
    Scan {
        exec: Ark<ScanExec>,
        obj_root: Ark<F>,
        cb_memb_root: Ark<F>,
        cb_nmemb_root: Ark<F>,
    },

    /// A group admin's PERMANENT BAN of the author of post `target`: its callback is
    /// invoked with `BAN_FLAG` at the next barrier, with no poll and nothing anyone can
    /// vote down. Carries no proof; like [`Record::RejoinApprove`] it is sent under the
    /// admin's own account and the client ingests it only from a Signal group admin.
    Ban { target: Eh },
}

impl Record {
    /// The variant name, for logging and the outcome report.
    pub fn kind(&self) -> &'static str {
        match self {
            Record::Join { .. } => "Join",
            Record::Post { .. } => "Post",
            Record::Rate { .. } => "Rate",
            Record::PollOpen { .. } => "PollOpen",
            Record::Vote { .. } => "Vote",
            Record::Scan { .. } => "Scan",
            Record::BadgeRequest { .. } => "BadgeRequest",
            Record::BadgeApprove { .. } => "BadgeApprove",
            Record::RejoinApprove { .. } => "RejoinApprove",
            Record::Ban { .. } => "Ban",
        }
    }

    /// Whether another member may relay this record (§5.5). A join, a re-join approval
    /// and an admin ban are accepted only because of who sent them over the messenger
    /// (the joining account, a group admin), which a relay would hide; every other
    /// record stands on its proof or its content alone.
    pub fn relayable(&self) -> bool {
        !matches!(
            self,
            Record::Join { .. }
                | Record::RejoinApprove { .. }
                | Record::Ban { .. }
                | Record::BadgeApprove { .. }
        )
    }
}

// ---------------------------------------------------------------------------------------
// The view claim
// ---------------------------------------------------------------------------------------

/// The sender's view of the group when it sent a record: the replica's
/// [view digest](super::Replica::view_digest) at `barrier` (`SERVERLESS_PROTOCOL.md`
/// §5.5).
///
/// The digest chains over every record placed at each barrier up to `barrier`, so two
/// members whose claims for the same barrier agree have seen exactly the same records
/// up to it. The messenger can delay or drop a record for some members only, and a
/// receiver that compares claims with its own digest detects that it did. The claim
/// rides in the envelope, so the record's [`Eh`] covers it. Nobody but the sender can
/// change it: the payload is end-to-end encrypted, and a member who re-wraps someone
/// else's proof under a different claim spends the same nullifier twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewClaim {
    pub barrier: u64,
    pub digest: [u8; 32],
}

// ---------------------------------------------------------------------------------------
// The envelope and its codec
// ---------------------------------------------------------------------------------------

/// The owned form, for decoding.
///
/// `view` is optional on the wire both ways: a record without a claim encodes exactly
/// as it did before claims existed (so its `Eh` is unchanged), and a reader that
/// predates claims ignores the field.
#[derive(Deserialize)]
struct Envelope {
    v: u16,
    record: Record,
    #[serde(default)]
    view: Option<ViewClaim>,
}

/// The borrowed form, for encoding — a `Record` is not `Clone`, so the envelope
/// borrows it rather than taking a copy.
#[derive(Serialize)]
struct EnvelopeRef<'a> {
    v: u16,
    record: &'a Record,
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<ViewClaim>,
}

/// A record failed to encode or decode.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("could not encode a {kind} record: {source}")]
    Encode {
        kind: &'static str,
        source: ciborium::ser::Error<std::io::Error>,
    },
    #[error("not a serverless record: {0}")]
    Malformed(String),
    #[error("record is serverless version {found}, this build speaks version {SERVERLESS_VERSION}")]
    Version { found: u16 },
}

/// Encode a record and return the bytes together with their [`Eh`].
///
/// The two always travel together, so no caller computes an identity of its own.
pub fn encode(record: &Record) -> Result<(Vec<u8>, Eh), CodecError> {
    encode_with_view(record, None)
}

/// [`encode`], carrying the sender's [`ViewClaim`].
pub fn encode_with_view(
    record: &Record,
    view: Option<ViewClaim>,
) -> Result<(Vec<u8>, Eh), CodecError> {
    let envelope = EnvelopeRef {
        v: SERVERLESS_VERSION,
        record,
        view,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&envelope, &mut bytes).map_err(|source| CodecError::Encode {
        kind: record.kind(),
        source,
    })?;
    let eh = identity(record)?;
    Ok((bytes, eh))
}

fn hash_fields(h: &mut Blake2s256, fields: &[F]) {
    for field in fields {
        h.update(field.into_bigint().to_bytes_le());
    }
}

fn hash_bytes(h: &mut Blake2s256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

/// The field element a proof binds as its payload, from a tagged hash.
fn payload_of(tag: &[u8], write: impl FnOnce(&mut Blake2s256)) -> F {
    let mut h = Blake2s256::new();
    hash_bytes(&mut h, tag);
    write(&mut h);
    F::from_le_bytes_mod_order(&h.finalize())
}

/// The payload of a post: its text.
pub fn post_payload(body: &str) -> F {
    payload_of(b"personas post", |h| hash_bytes(h, body.as_bytes()))
}

/// The payload of a ballot: the poll and the option chosen.
pub fn ballot_payload(poll: Eh, option: u32) -> F {
    payload_of(b"personas ballot", |h| {
        h.update(poll.0);
        h.update(option.to_le_bytes());
    })
}

/// The payload of a rating: the record rated and by how much.
pub fn rating_payload(target: Eh, delta: i8) -> F {
    payload_of(b"personas rating", |h| {
        h.update(target.0);
        h.update(delta.to_le_bytes());
    })
}

/// A record's [`Eh`].
///
/// A proof-carrying record is identified by its statement, the values its proof is about.
/// Anything else in its bytes can be changed by whoever relays it, and a copy that differed
/// only there must count as the same record, or it could displace the original and leave
/// bans and ratings aimed at nothing. A scan is not identified this way: nothing refers to
/// one, and its proof is checked against state that changes, so its identity includes the
/// proof and a forged copy cannot stand in for it.
pub fn identity(record: &Record) -> Result<Eh, CodecError> {
    let mut h = Blake2s256::new();
    hash_bytes(&mut h, record.kind().as_bytes());
    match record {
        Record::Join {
            object,
            account,
            pk,
            ..
        } => hash_fields(&mut h, &[object.0, account.0, pk.0]),
        Record::Post {
            flavour,
            exec,
            extra,
            payload,
            obj_root,
            ..
        } => {
            h.update([*flavour as u8]);
            hash_fields(
                &mut h,
                &[exec.0.new_object, exec.0.old_nullifier, exec.0.cb_com_list[0]],
            );
            hash_fields(&mut h, &extra.0);
            hash_fields(&mut h, &[payload.0, obj_root.0]);
        }
        Record::BadgeRequest {
            exec,
            slot,
            obj_root,
        } => {
            h.update([*slot]);
            hash_fields(
                &mut h,
                &[
                    exec.0.new_object,
                    exec.0.old_nullifier,
                    exec.0.cb_com_list[0],
                    obj_root.0,
                ],
            );
        }
        Record::Rate {
            target,
            delta,
            claimed,
            obj_root,
            ..
        } => {
            h.update(target.0);
            h.update(delta.to_le_bytes());
            hash_fields(&mut h, &[claimed.0, obj_root.0]);
        }
        Record::Vote {
            poll,
            option,
            claimed,
            obj_root,
            ..
        } => {
            h.update(poll.0);
            h.update(option.to_le_bytes());
            hash_fields(&mut h, &[claimed.0, obj_root.0]);
        }
        Record::RejoinApprove { account, spent } => {
            hash_fields(&mut h, &[account.0]);
            if let Some(spent) = spent {
                hash_fields(&mut h, &[spent.nul.0, spent.root.0]);
            }
        }
        Record::Scan { .. }
        | Record::PollOpen { .. }
        | Record::BadgeApprove { .. }
        | Record::Ban { .. } => {
            let mut bytes = Vec::new();
            let envelope = EnvelopeRef {
                v: SERVERLESS_VERSION,
                record,
                view: None,
            };
            ciborium::into_writer(&envelope, &mut bytes).map_err(|source| CodecError::Encode {
                kind: record.kind(),
                source,
            })?;
            hash_bytes(&mut h, &bytes);
        }
    }
    Ok(Eh(h.finalize().into()))
}

/// Decode a record, returning it with its [`Eh`] recomputed — so a decoded record's
/// identity is what any other replica would compute, not something the sender could
/// assert.
pub fn decode(bytes: &[u8]) -> Result<(Record, Eh), CodecError> {
    decode_with_view(bytes).map(|(record, eh, _)| (record, eh))
}

/// [`decode`], also returning the sender's [`ViewClaim`] if the record carries one.
pub fn decode_with_view(bytes: &[u8]) -> Result<(Record, Eh, Option<ViewClaim>), CodecError> {
    let envelope: Envelope = ciborium::from_reader(bytes)
        .map_err(|e| CodecError::Malformed(format!("could not read envelope: {e}")))?;
    if envelope.v != SERVERLESS_VERSION {
        return Err(CodecError::Version { found: envelope.v });
    }
    let eh = identity(&envelope.record)?;
    Ok((envelope.record, eh, envelope.view))
}

/// The record re-encoded WITHOUT its private text — a post's body, a poll's question
/// and option labels (the number of options stays: a vote names one by index) — for
/// handing to a late joiner who should not read the group's past messages.
///
/// A stripped poll no longer has its original [`Eh`], so whoever stores it must keep that
/// beside it ([`super::Replica::import_records`]). Nothing the replica derives depends on
/// the removed text: a post's proof covers `payload`, which stays, and ratings and polls
/// refer to records by their original `Eh`.
pub fn strip_private_text(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    let (mut record, _, view) = decode_with_view(bytes)?;
    match &mut record {
        Record::Post { body, .. } => body.clear(),
        Record::PollOpen {
            question, options, ..
        } => {
            question.clear();
            options.iter_mut().for_each(String::clear);
        }
        _ => {}
    }
    Ok(encode_with_view(&record, view)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn a_join_round_trips_and_its_eh_is_stable() {
        let mut rng = StdRng::seed_from_u64(1);
        let rec = Record::Join {
            object: Ark(F::rand(&mut rng)),
            old_nul: Ark(F::rand(&mut rng)),
            account: Ark(F::rand(&mut rng)),
            pk: Ark(F::rand(&mut rng)),
            proof: Ark(PredProof::default()),
        };
        let (bytes, eh) = encode(&rec).unwrap();
        let (back, eh2) = decode(&bytes).unwrap();
        assert_eq!(eh, eh2, "decode recomputes the same eh");
        match back {
            Record::Join {
                object, old_nul, ..
            } => {
                let Record::Join {
                    object: o0,
                    old_nul: n0,
                    ..
                } = &rec
                else {
                    unreachable!()
                };
                assert_eq!(object.0, o0.0);
                assert_eq!(old_nul.0, n0.0);
            }
            _ => panic!("wrong kind"),
        }
        // Re-encoding is byte-identical, so the eh is a function of content alone.
        let (bytes2, _) = encode(&rec).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn distinct_records_have_distinct_ehs() {
        let a = Record::PollOpen {
            question: "ban?".into(),
            options: vec!["yes".into(), "no".into()],
            kind: PollKind::Ban,
            target: None,
        };
        let b = Record::PollOpen {
            question: "ban!".into(),
            options: vec!["yes".into(), "no".into()],
            kind: PollKind::Ban,
            target: None,
        };
        let (_, ea) = encode(&a).unwrap();
        let (_, eb) = encode(&b).unwrap();
        assert_ne!(ea, eb);
        // And the context each derives is likewise distinct and deterministic.
        assert_ne!(ea.context(), eb.context());
        assert_eq!(ea.context(), ea.context());
    }

    #[test]
    fn a_future_version_is_refused() {
        let rec = Record::PollOpen {
            question: "q".into(),
            options: vec![],
            kind: PollKind::Standard,
            target: None,
        };
        let (bytes, _) = encode(&rec).unwrap();
        // Hand-craft an envelope one version ahead.
        let mut ahead = Vec::new();
        ciborium::into_writer(
            &EnvelopeRef {
                v: SERVERLESS_VERSION + 1,
                record: &rec,
                view: None,
            },
            &mut ahead,
        )
        .unwrap();
        assert!(matches!(
            decode(&ahead),
            Err(CodecError::Version { found }) if found == SERVERLESS_VERSION + 1
        ));
        // The well-formed one still decodes.
        assert!(decode(&bytes).is_ok());
    }

    #[test]
    fn a_view_claim_round_trips_and_is_not_part_of_the_eh() {
        let rec = Record::PollOpen {
            question: "q".into(),
            options: vec!["a".into()],
            kind: PollKind::Standard,
            target: None,
        };
        let claim = ViewClaim {
            barrier: 7,
            digest: [9; 32],
        };
        let (plain, plain_eh) = encode(&rec).unwrap();
        let (bytes, eh) = encode_with_view(&rec, Some(claim)).unwrap();
        assert_eq!(eh, plain_eh, "the claim is outside every proof, so not the identity");
        let (_, eh2, back) = decode_with_view(&bytes).unwrap();
        assert_eq!((eh2, back), (eh, Some(claim)));
        // A record without a claim reads back without one, and still decodes plainly.
        assert_eq!(decode_with_view(&plain).unwrap().2, None);
        assert!(decode(&bytes).is_ok());
        // Stripping private text keeps the claim.
        let stripped = strip_private_text(&bytes).unwrap();
        assert_eq!(decode_with_view(&stripped).unwrap().2, Some(claim));
    }

    #[test]
    fn a_record_without_a_claim_encodes_as_before_claims_existed() {
        // The pre-claim envelope had exactly two fields. Byte-identical encoding keeps
        // every journaled record's eh stable.
        #[derive(Serialize)]
        struct Old<'a> {
            v: u16,
            record: &'a Record,
        }
        let rec = Record::Ban {
            target: Eh([1; 32]),
        };
        let mut old = Vec::new();
        ciborium::into_writer(
            &Old {
                v: SERVERLESS_VERSION,
                record: &rec,
            },
            &mut old,
        )
        .unwrap();
        assert_eq!(encode(&rec).unwrap().0, old);
    }

    #[test]
    fn garbage_is_not_a_record() {
        assert!(matches!(decode(b"not cbor"), Err(CodecError::Malformed(_))));
    }
}
