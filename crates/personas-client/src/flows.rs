//! The proving flows: everything a member can do that produces a proof.
//!
//! Each flow loads the `User` object, proves the relevant predicate against the
//! bulletin, advances the object, and saves it back. The returned bytes are the payload
//! the caller posts to the server. **The user object must be saved on every success** —
//! a flow that proves but does not persist leaves the client's committed state behind
//! the bulletin's, and every later proof against it fails.

use anyhow::{Context, Result, anyhow};
use ark_bn254::G1Projective as Projective;
use ark_ff::PrimeField;
use ark_grumpkin::Projective as Projective2;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use folding_schemes::{
    FoldingScheme, commitment::pedersen::Pedersen, folding::nova::Nova,
    folding::nova::zk::RandomizedIVCProof, frontend::FCircuit,
};
use hex::FromHex;
use personas_wire::{Kind, Payload};

use personas_core::{
    Args, ArgsVar, Cr, F, H, OStore, Snark,
    circuits::{
        BadgesArgs, BadgesArgsVar, FoldingProofData, MsgUser, NUM_SCANS_PER_FOLD, PseudonymArgs,
        PseudonymArgsPair, PseudonymArgsPairVar, PseudonymArgsRate, PseudonymArgsVar,
        authorship_pred, badge_pred, exec_badge_request_standint, exec_pseudo_rate_standint,
        exec_pseudo_standint, exec_scanint, exec_standint, get_callbacks, pseudonym_pred,
    },
    timing::{append_proof_size_fold, append_timing_line, append_timing_line_fold},
};
use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json::json;
use std::time::SystemTime;
use zk_callbacks::{
    generic::{
        bulletin::PublicUserBul, callbacks::CallbackCom, fold::FoldingScan, object::Time,
        user::User,
    },
    impls::centralized::crypto::PlainTikCrypto,
};

use crate::{BulNet, PersonaClient};

/// The Nova instance folding `NUM_SCANS_PER_FOLD` callback scans per step.
pub type NFC = Nova<
    Projective,
    Projective2,
    FoldingScan<F, MsgUser, Args, ArgsVar, Cr, BulNet, BulNet, H, NUM_SCANS_PER_FOLD>,
    Pedersen<Projective, true>,
    Pedersen<Projective2, true>,
    true,
>;

/// A callback the server issued for a message, keyed how that transport names messages.
#[derive(Clone, Debug)]
pub enum MessageId {
    /// Signal identifies a message by its send timestamp.
    Signal(u64),
    /// Slack identifies a message by its `ts` string, which is not an integer.
    Slack(String),
}

impl MessageId {
    /// The route that hands back the callback the server minted for this message.
    fn callback_route(&self) -> &'static str {
        match self {
            MessageId::Signal(_) => "api/cb",
            MessageId::Slack(_) => "api/slack_cb",
        }
    }

    fn body(&self) -> serde_json::Value {
        match self {
            MessageId::Signal(t) => json!({ "timestamp": t }),
            MessageId::Slack(t) => json!({ "timestamp": t }),
        }
    }
}

#[derive(Deserialize)]
struct EpochResponse {
    epoch: String,
}

/// Upstream `User` panics (`assert!(self.scan_index.is_none())`) if any non-scan
/// interaction is attempted while a callback sweep is unfinished — a member with more
/// than one outstanding callback needs multiple `scan` calls to complete one sweep, and
/// `scan_index` stays `Some` on disk in between. Turn that panic into a clear error.
/// See FINDINGS O2.
fn ensure_not_scanning(user: &User<F, MsgUser>) -> Result<()> {
    if user.is_scanning() {
        return Err(anyhow!(
            "you have an unfinished callback scan ({} outstanding); run `scan` until it \
             completes before doing anything else",
            user.num_outstanding_callbacks()
        ));
    }
    Ok(())
}

/// A membership witness for the object bulletin: its public part and its witness.
type Membership = (
    <BulNet as PublicUserBul<F, MsgUser>>::MembershipPub,
    <BulNet as PublicUserBul<F, MsgUser>>::MembershipWitness,
);

impl PersonaClient {
    /// The current epoch. Scans and pseudonymous posts are bound to it, so a callback
    /// can only be answered inside the window it was issued in.
    pub fn epoch(&self) -> Result<F> {
        let url = self.cfg.url("api/get_epoch")?;
        let res: EpochResponse = self
            .bul
            .client
            .get(url)
            .send()
            .context("failed to fetch the current epoch")?
            .json()
            .context("server returned a malformed epoch")?;

        let bytes = hex::decode(&res.epoch).context("epoch is not valid hex")?;
        Ok(F::from_le_bytes_mod_order(&bytes))
    }

    /// The member's current reputation, as recorded in their local user object.
    pub fn reputation(&self) -> Result<String> {
        Ok(self.load_user()?.data.reputation.into_bigint().to_string())
    }

    /// How many callbacks are still outstanding against this member's object — including
    /// any left over from an unfinished sweep. Zero means `scan` has nothing to do and no
    /// other command will trip the mid-sweep guard (`ensure_not_scanning`, FINDINGS O2).
    pub fn outstanding_callbacks(&self) -> Result<usize> {
        Ok(self.load_user()?.num_outstanding_callbacks())
    }

    /// Whether a callback sweep is unfinished — `scan` needs to be called again to
    /// complete it before any other proving flow will succeed. See FINDINGS O2.
    pub fn is_scanning(&self) -> Result<bool> {
        Ok(self.load_user()?.is_scanning())
    }

    /// Post a message: prove the standard predicate (under the rate limit, not banned)
    /// and mint the callback that lets the group act on this message later.
    pub fn gen_cb_for_msg(&self) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let mut user = self.load_user()?;
        ensure_not_scanning(&user)?;
        let pk = self.standard_pk();

        let start = SystemTime::now();
        let exec = exec_standint(
            &mut user,
            &mut rng,
            &self.bul,
            &pk,
            Time::from(0),
            F::from(0),
            (),
        )
        .map_err(synthesis)?;
        record("anon_msg", start);

        let payload = encode_record(Kind::Post, &exec)?;
        self.save_user(&user)?;
        Ok(payload)
    }

    /// Request badge slot `index`, claimed under the pseudonym `badge`.
    pub fn gen_cb_for_badge_request(&self, index: u32, badge: F) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let mut user = self.load_user()?;
        ensure_not_scanning(&user)?;
        let pk = self.badge_request_pk();
        let epoch = self.epoch()?;

        let i_f = F::from(index);
        let args = BadgesArgs {
            i: i_f,
            claimed: badge,
        };

        let exec =
            exec_badge_request_standint(&mut user, &mut rng, &self.bul, &pk, epoch, args, ())
                .map_err(synthesis)?;

        let payload = encode_record_with_inputs(Kind::BadgeRequest, &exec, vec![i_f, badge])?;

        self.save_user(&user)?;
        Ok(payload)
    }

    /// Answer one outstanding callback.
    pub fn scan(&self) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let mut user = self.load_user()?;
        let pk = self.scan_pk();
        let epoch = self.epoch()?;

        let start = SystemTime::now();
        let scan = exec_scanint::<_, _, NUM_SCANS_PER_FOLD>(
            &mut user, &mut rng, &self.bul, &pk, &self.bul, epoch,
        )
        .map_err(synthesis)?;
        record("scan", start);

        let payload = encode_record(Kind::Scan, &scan)?;
        self.save_user(&user)?;
        Ok(payload)
    }

    /// Answer every outstanding callback in one Nova-folded proof.
    ///
    /// Note this folds `k / NUM_SCANS_PER_FOLD` steps and so silently drops the
    /// `k mod NUM_SCANS_PER_FOLD` remainder — the fold-size menu is what fixes that.
    pub fn fold(&self) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let mut user = self.load_user()?;

        let epoch = self.epoch()?;
        let cb_methods = get_callbacks();
        let folding_key = self.fold_pk();

        let memb = <BulNet as PublicUserBul<F, MsgUser>>::get_membership_data(
            &self.bul,
            user.commit::<H>(),
        )
        .ok_or_else(|| anyhow!("this user is not on the bulletin; run `join` first"))?;

        let steps = user.num_outstanding_callbacks() / NUM_SCANS_PER_FOLD;

        let (params, init, v, extra_verif) = user
            .scan_and_create_fold_proof_inputs::<_, _, _, _, _, H, Snark, NUM_SCANS_PER_FOLD>(
                &mut rng,
                memb,
                &self.bul,
                true,
                (true, true),
                epoch,
                cb_methods,
                &folding_key,
                steps,
            );

        let f_circ: FoldingScan<
            F,
            MsgUser,
            Args,
            ArgsVar,
            Cr,
            BulNet,
            BulNet,
            H,
            NUM_SCANS_PER_FOLD,
        > = FoldingScan::new(params).map_err(|e| anyhow!("failed to build fold circuit: {e}"))?;

        let nova_params = self.fold_params();
        let mut folding_scheme: NFC = NFC::init(&nova_params, f_circ, init)
            .map_err(|e| anyhow!("failed to initialize Nova: {e}"))?;

        debug_assert!(!user.is_scanning());

        let start = SystemTime::now();
        for step in v.iter().take(steps) {
            folding_scheme
                .prove_step(&mut rng, step.clone(), None)
                .map_err(|e| anyhow!("Nova fold step failed: {e}"))?;
        }
        record_fold("fold", start, "step");

        // Nova's IVC proof is not zero-knowledge on its own; randomizing it is what
        // keeps the folded scan from leaking the witness.
        let start_proof = SystemTime::now();
        let proof = RandomizedIVCProof::new(&folding_scheme, &mut rng)
            .map_err(|e| anyhow!("failed to randomize the IVC proof: {e}"))?;
        record_fold("fold", start_proof, "proof");

        let data = FoldingProofData {
            proof,
            i: folding_scheme.i,
            z_0: folding_scheme.z_0,
            z_i: folding_scheme.z_i,
            extra_verif,
        };

        // The bare proof is measured, not sent: the plot wants the proof's own size next to
        // the size of the record that carries it.
        let proof_only = personas_wire::raw::encode(&data.proof)
            .map_err(|e| anyhow!("failed to size the folded proof: {e}"))?;
        let payload = encode_record(Kind::FoldScan, &data)?;

        if let Err(e) = append_proof_size_fold(
            "fold",
            proof_only.len(),
            payload.len(),
            NUM_SCANS_PER_FOLD,
            "proof_size",
        ) {
            eprintln!("failed to record fold proof size: {e}");
        }

        self.save_user(&user)?;
        Ok(payload)
    }

    /// Post under a pseudonym: prove `claimed = H(sk, context)` alongside the standard
    /// predicate, so the message is attributable to a persona but not to a member.
    pub fn pseudo_proof_with_msg(&self, claimed: F, context: F) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let mut user = self.load_user()?;
        ensure_not_scanning(&user)?;
        let pk = self.standard_pseudo_pk();
        let epoch = self.epoch()?;

        let pseudo = PseudonymArgs {
            context,
            claimed,
            ..Default::default()
        };

        let start = SystemTime::now();
        let exec = exec_pseudo_standint(&mut user, &mut rng, &self.bul, &pk, epoch, pseudo, ())
            .map_err(synthesis)?;
        record("pseudo_msg", start);

        let payload = encode_record_with_inputs(Kind::PostPseudo, &exec, vec![context, claimed])?;

        self.save_user(&user)?;
        Ok(payload)
    }

    /// Post under the `i`-th rate-limited pseudonym for `context`, which caps how many
    /// personas one member can wear in a single thread.
    pub fn rate_pseudo_proof_with_msg(&self, claimed: F, context: F, i: F) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let mut user = self.load_user()?;
        ensure_not_scanning(&user)?;
        let pk = self.standard_pseudo_rate_pk();

        let pseudo = PseudonymArgsRate {
            context,
            claimed,
            i,
            ..Default::default()
        };

        let start = SystemTime::now();
        let exec = exec_pseudo_rate_standint(
            &mut user,
            &mut rng,
            &self.bul,
            &pk,
            Time::from(0),
            pseudo,
            (),
        )
        .map_err(synthesis)?;
        record("rate_pseudo", start);

        let payload =
            encode_record_with_inputs(Kind::PostPseudoRate, &exec, vec![context, claimed, i])?;

        self.save_user(&user)?;
        Ok(payload)
    }

    /// Prove a pseudonym for a vote. Unlike a post this proves the predicate *only* —
    /// it does not advance the user object, so voting costs no rate-limit budget.
    pub fn pseudo_proof_vote(&self, claimed: F, context: F) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let user = self.load_user()?;
        ensure_not_scanning(&user)?;

        let (pubkey, sig) = self
            .membership(&user)
            .ok_or_else(|| anyhow!("this user is not on the bulletin; run `join` first"))?;
        let pk = self.pseudonym_pred_pk();

        let pseudo = PseudonymArgs {
            context,
            claimed,
            ..Default::default()
        };

        let start = SystemTime::now();
        let proof = user
            .prove_statement_and_in::<H, PseudonymArgs<F>, PseudonymArgsVar<F>, (), (), Snark, OStore>(
                &mut rng,
                pseudonym_pred,
                &pk,
                (sig, pubkey),
                true,
                pseudo,
                (),
            )
            .map_err(synthesis)?;
        record("pseudo_vote", start);

        let payload = encode_record_with_inputs(Kind::Predicate, &proof, vec![context, claimed])?;

        Ok(payload)
    }

    /// Prove that the pseudonyms at log indices `i1` and `i2` share an author — the
    /// member claims both personas without revealing who they are.
    pub fn make_authorship_proof(&self, i1: usize, i2: usize) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let user = self.load_user()?;
        ensure_not_scanning(&user)?;

        let (pubkey, sig) = self
            .membership(&user)
            .ok_or_else(|| anyhow!("this user is not on the bulletin; run `join` first"))?;
        let pk = self.authorship_pred_pk();

        let (claimed1, context1) = self.pseudonym_at(i1)?;
        let (claimed2, context2) = self.pseudonym_at(i2)?;

        let pair = PseudonymArgsPair {
            a: PseudonymArgs {
                context: context1,
                claimed: claimed1,
                ..Default::default()
            },
            b: PseudonymArgs {
                context: context2,
                claimed: claimed2,
                ..Default::default()
            },
        };

        let start = SystemTime::now();
        let proof = user
            .prove_statement_and_in::<H, PseudonymArgsPair<F>, PseudonymArgsPairVar<F>, (), (), Snark, OStore>(
                &mut rng,
                authorship_pred,
                &pk,
                (sig, pubkey),
                true,
                pair,
                (),
            )
            .map_err(synthesis)?;
        record("author", start);

        let payload = encode_record_with_inputs(
            Kind::Predicate,
            &proof,
            vec![context1, claimed1, context2, claimed2],
        )?;

        Ok(payload)
    }

    /// Prove badge slot `i` is held under the pseudonym `badge`.
    pub fn make_badge_proof(&self, i: u32, badge: F) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let user = self.load_user()?;
        ensure_not_scanning(&user)?;

        let (pubkey, sig) = self
            .membership(&user)
            .ok_or_else(|| anyhow!("this user is not on the bulletin; run `join` first"))?;
        let pk = self.badge_pred_pk();

        let i_f = F::from(i);
        let args = BadgesArgs {
            i: i_f,
            claimed: badge,
        };

        let start = SystemTime::now();
        let proof = user
            .prove_statement_and_in::<H, BadgesArgs<F>, BadgesArgsVar<F>, (), (), Snark, OStore>(
                &mut rng,
                badge_pred,
                &pk,
                (sig, pubkey),
                true,
                args,
                (),
            )
            .map_err(synthesis)?;
        record("badge", start);

        let payload = encode_record_with_inputs(Kind::Predicate, &proof, vec![i_f, badge])?;

        Ok(payload)
    }

    /// Fetch the callback the server minted for `msg` and hand it back to `endpoint`,
    /// which is how the group invokes it (ban, reputation, badge approval).
    pub fn send_callback_to_endpoint(&self, msg: &MessageId, endpoint: &str) -> Result<()> {
        let cb_url = self.cfg.url(msg.callback_route())?;
        let resp = self
            .bul
            .client
            .post(cb_url)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&msg.body())?)
            .send()
            .context("failed to fetch the callback for this message")?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "server has no callback for this message (status {})",
                resp.status()
            ));
        }

        let cb: CallbackCom<F, Args, PlainTikCrypto<F>> =
            CanonicalDeserialize::deserialize_compressed(&*resp.bytes()?)
                .map_err(|e| anyhow!("server returned an undecodable callback: {e}"))?;

        self.bul
            .client
            .post(self.cfg.url(endpoint)?)
            .body(callback_bytes(&cb)?)
            .send()
            .with_context(|| format!("failed to invoke the callback at {endpoint}"))?;

        Ok(())
    }

    /// Invoke a message's callback to ban its author.
    pub fn ban(&self, msg: &MessageId) -> Result<()> {
        self.send_callback_to_endpoint(msg, "api/ban")
    }

    /// Invoke a message's callback to apply its accrued reputation.
    pub fn rep(&self, msg: &MessageId) -> Result<()> {
        self.send_callback_to_endpoint(msg, self.cfg.namespace.reputation_route())
    }

    /// Apply every reputation callback the server is holding.
    pub fn process_reputation_updates(&self) -> Result<()> {
        let route = self.cfg.namespace.reputation_route();
        self.drain_callbacks(
            self.cfg.namespace.all_callbacks_route(),
            route,
            "reputation",
        )
    }

    /// Apply every badge-request callback the server is holding (approves the requests).
    pub fn process_badge_updates(&self) -> Result<()> {
        self.drain_callbacks("api/cb/badge/requests", "api/approve/badge", "badge")
    }

    /// Fetch the hex-encoded callbacks listed at `list_route` and replay each into
    /// `target_route`. One failed callback does not abort the rest.
    fn drain_callbacks(&self, list_route: &str, target_route: &str, what: &str) -> Result<()> {
        let resp = self
            .bul
            .client
            .get(self.cfg.url(list_route)?)
            .send()
            .with_context(|| format!("failed to list {what} callbacks"))?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "failed to list {what} callbacks (status {})",
                resp.status()
            ));
        }

        let cb_hex_list: Vec<String> = resp
            .json()
            .with_context(|| format!("server returned a malformed {what} callback list"))?;

        let target = self.cfg.url(target_route)?;

        for cb_hex in cb_hex_list {
            let bytes = Vec::from_hex(&cb_hex)
                .with_context(|| format!("{what} callback is not valid hex: {cb_hex}"))?;

            let cb: CallbackCom<F, Args, PlainTikCrypto<F>> =
                CanonicalDeserialize::deserialize_compressed(&bytes[..])
                    .map_err(|e| anyhow!("{what} callback {cb_hex} is undecodable: {e}"))?;

            let resp = self
                .bul
                .client
                .post(target.clone())
                .body(callback_bytes(&cb)?)
                .send()
                .with_context(|| format!("failed to submit {what} callback {cb_hex}"))?;

            if !resp.status().is_success() {
                eprintln!(
                    "server rejected {what} callback {cb_hex} (status {})",
                    resp.status()
                );
            }
        }

        Ok(())
    }

    /// The membership witness proving this user is on the object bulletin.
    fn membership(&self, user: &User<F, MsgUser>) -> Option<Membership> {
        <BulNet as PublicUserBul<F, MsgUser>>::get_membership_data(&self.bul, user.commit::<H>())
    }

    /// The `(claimed, context)` field elements at a 1-based pseudonym-log index.
    fn pseudonym_at(&self, index: usize) -> Result<(F, F)> {
        let (claimed, context) = self.claimed_context_by_index(index)?;
        Ok((
            personas_core::persona::field_from_str(&claimed)
                .ok_or_else(|| anyhow!("pseudonym {index} has a malformed claimed value"))?,
            personas_core::persona::field_from_str(&context)
                .ok_or_else(|| anyhow!("pseudonym {index} has a malformed context"))?,
        ))
    }
}

/// zk-callbacks reports proving failures as `SynthesisError`, which carries no context.
fn synthesis(e: SynthesisError) -> anyhow::Error {
    anyhow!("proof generation failed: {e}")
}

/// A record: a versioned envelope around a compressed arkworks payload.
///
/// The `Compress::No`, no-header convention this replaces was agreed between the client and
/// the server by nothing but habit — each route defined its own implicit format, and a record
/// carried no indication of what it was. `personas-wire` owns the format now; see its module
/// docs for why records are compressed and proving keys are not.
fn encode_record<T: CanonicalSerialize>(kind: Kind, value: &T) -> Result<Vec<u8>> {
    personas_wire::encode_one(kind, value)
        .map_err(|e| anyhow!("failed to encode a {kind:?} record: {e}"))
}

/// A record whose payload is a proof followed by the public inputs it is checked against.
fn encode_record_with_inputs<T: CanonicalSerialize>(
    kind: Kind,
    value: &T,
    inputs: Vec<F>,
) -> Result<Vec<u8>> {
    let mut payload = Payload::new(kind);
    payload
        .push(value)
        .and_then(|p| p.push(&inputs))
        .map_err(|e| anyhow!("failed to encode a {kind:?} record: {e}"))?;

    personas_wire::encode(payload).map_err(|e| anyhow!("failed to encode a {kind:?} record: {e}"))
}

/// A callback commitment, as the server's ledger keys it: canonical, uncompressed, no
/// envelope.
///
/// Not a record. These bytes are a *name* — the server hex-encodes exactly them to look the
/// callback up — so the encoding has to match on both sides byte for byte. (It happens to be
/// insensitive to the compression flag, since a `CallbackCom` is all field elements and those
/// serialize identically either way, which is why the mismatched pair of `deserialize_compressed`
/// here and `Compress::No` on the server has been working.)
fn callback_bytes<T: CanonicalSerialize>(cb: &T) -> Result<Vec<u8>> {
    personas_wire::raw::encode(cb).map_err(|e| anyhow!("failed to serialize the callback: {e}"))
}

/// Instrumentation is best-effort: a failed benchmark write must never fail a proof.
pub(crate) fn record(label: &str, start: SystemTime) {
    if let Ok(elapsed) = start.elapsed()
        && let Err(e) = append_timing_line(label, start, elapsed.as_secs_f64() * 1e3)
    {
        eprintln!("failed to record timing for {label}: {e}");
    }
}

fn record_fold(label: &str, start: SystemTime, suffix: &str) {
    if let Ok(elapsed) = start.elapsed()
        && let Err(e) = append_timing_line_fold(
            label,
            start,
            elapsed.as_secs_f64() * 1e3,
            NUM_SCANS_PER_FOLD,
            suffix,
        )
    {
        eprintln!("failed to record fold timing for {label}: {e}");
    }
}
