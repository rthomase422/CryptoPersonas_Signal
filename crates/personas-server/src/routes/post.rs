//! Posting: verify the proof, append to the bulletin, relay the message, file the callback.
//!
//! Six handlers used to live here — anonymous, pseudonymous and rate-limited, once for
//! Signal and once for Slack — each ~180 lines, differing in which verifying key they used,
//! which public arguments they built, and whether they shelled out to `signal-cli-client` or
//! called slack-morphism. They are one function now; [`Flavour`] is the difference.
//!
//! # The order matters
//!
//! 1. Verify the proof and append to the bulletin.
//! 2. Relay the message — and only now does it have an id.
//! 3. File the callback the poster committed to, under that id.
//!
//! The old code did (1), then wrote a half-row holding the callback and no id, then relayed,
//! then went back and rewrote *the last line of the file* to add the id. If the relay failed,
//! the half-row stayed, and the next member's post adopted it — filing one member's callback
//! against another member's message. Nothing can be filed before the id exists, so nothing is.
//!
//! Note that (1) is not undone if (2) fails. The bulletin has already accepted the
//! interaction, the member has spent it, and the messenger did not deliver. That was true
//! before and is true now; making it atomic means a bulletin that can roll back, which the
//! bulletin cannot.

use ark_ff::PrimeField;
use axum::extract::{Json, State};
use axum::response::Response;
use personas_core::circuits::{BadgesArgs, PseudonymArgs, PseudonymArgsRate};
use personas_core::{Args, Cr, F, Snark, VK, persona};
use personas_wire::{Kind, decode};
use serde::Deserialize;
use zk_callbacks::generic::user::ExecutedMethod;

use transport_api::{Attachment, ConversationId, MessageId, Outgoing};

use crate::bench;
use crate::bulletin::{INTERACTION, epoch, verify_and_store};
use crate::error::{AppError, AppResult, ok};
use crate::state::{Namespace, ServerLock, ServerState, StoredBadge, badge_name, emoji_for};

// ---------------------------------------------------------------------------------------
// Request bodies. The two messengers name their destination differently — a Signal group id,
// a Slack channel — and that is the only difference between these.
// ---------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignalPost {
    pub message: String,
    pub group_id: String,
    pub proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SignalReply {
    pub group_id: String,
    pub message: String,
    pub timestamp: u64,
    pub proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SignalReact {
    pub group_id: String,
    pub emoji: String,
    pub timestamp: u64,
}

#[derive(Deserialize)]
pub struct SignalProofOnly {
    pub proof: Vec<u8>,
    pub group_id: String,
}

#[derive(Deserialize)]
pub struct SlackPost {
    pub channel: String,
    pub message: String,
    pub proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SlackReact {
    pub channel: String,
    pub emoji: String,
    pub timestamp: String,
}

#[derive(Deserialize)]
pub struct SlackProofOnly {
    pub channel: String,
    pub proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SlackClaimBadge {
    pub channel: String,
    pub badge_bytes: Vec<u8>,
    pub badge_name: String,
    pub proof: Vec<u8>,
}

/// What a post claims about its author.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavour {
    /// Nothing: an unlinkable post by some unbanned member.
    Anon,
    /// A pseudonym, scoped to a context. Two posts under the same pseudonym are the same
    /// member; posts under different pseudonyms cannot be linked.
    Pseudo,
    /// A pseudonym plus an index, so a member can be held to *k* posts per context.
    PseudoRate,
}

impl Flavour {
    fn kind(self) -> Kind {
        match self {
            Self::Anon => Kind::Post,
            Self::Pseudo => Kind::PostPseudo,
            Self::PseudoRate => Kind::PostPseudoRate,
        }
    }

    fn verifying_key(self, state: &ServerState) -> VK {
        match self {
            Self::Anon => state.keys.standard_verifying_key.clone(),
            Self::Pseudo => state.keys.standard_pseudo_verifying_key.clone(),
            Self::PseudoRate => state.keys.standard_pseudor_verifying_key.clone(),
        }
    }
}

/// What verification established, for the relay step to use.
struct Verified {
    /// Hex callback commitments, to be filed once the message has an id.
    callbacks: Vec<String>,
    /// The petname the message is posted under, if any.
    persona: Option<String>,
    /// The *thread* context, set only by a rate-limited post.
    ///
    /// Every pseudonymous post proves a context — that is what a pseudonym is scoped to — but
    /// only a rate-limited one proves a context that names a thread the server assigned. A
    /// plain pseudonym's context is minted client-side and belongs to no thread, so it is not
    /// carried here: it would send the message looking for a thread that does not exist.
    context: Option<String>,
}

/// Verify a post of any flavour, append it to the bulletin.
///
/// Every flavour files its callbacks at the live epoch (FINDINGS O3) — the old
/// disagreement (anonymous/rate-limited posts at `Time::from(0)`, pseudonymous posts at
/// the live epoch) was unobservable only because the sole callback in use is
/// `expirable: false`, but would silently drop tickets the day an expirable one is
/// introduced. See [`verify_and_store`].
fn verify_post(
    st: &mut ServerState,
    flavour: Flavour,
    proof: &[u8],
    label: &str,
) -> AppResult<Verified> {
    let vk = flavour.verifying_key(st);
    let mut reader = decode(flavour.kind(), proof)?;
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> = reader.pull()?;
    let current = epoch(&st.db);

    let (result, start, millis) = bench::time(|| match flavour {
        Flavour::Anon => verify_and_store(&mut st.db, &vk, exec, F::from(0), current, INTERACTION)
            .map(|callbacks| Verified {
                callbacks,
                persona: None,
                context: None,
            }),

        Flavour::Pseudo => {
            let inputs = pub_inputs(&mut reader, 2)?;
            let (context, claimed) = (inputs[0], inputs[1]);

            verify_and_store(
                &mut st.db,
                &vk,
                exec,
                PseudonymArgs {
                    context,
                    claimed,
                    ..Default::default()
                },
                current,
                INTERACTION,
            )
            .map(|callbacks| Verified {
                callbacks,
                persona: Some(persona::petname(claimed)),
                // Deliberately not the thread key. A plain pseudonymous post is scoped to a
                // context the *client* invented for that pseudonym; it names no thread, and
                // looking one up would refuse every post that is not a threaded reply.
                context: None,
            })
        }

        Flavour::PseudoRate => {
            let inputs = pub_inputs(&mut reader, 3)?;
            let (context, claimed, i) = (inputs[0], inputs[1], inputs[2]);

            verify_and_store(
                &mut st.db,
                &vk,
                exec,
                PseudonymArgsRate {
                    context,
                    claimed,
                    i,
                    ..Default::default()
                },
                current,
                INTERACTION,
            )
            .map(|callbacks| Verified {
                callbacks,
                persona: Some(persona::petname(claimed)),
                context: Some(field_to_string(context)),
            })
        }
    });

    bench::verified(label, start, millis);
    result
}

/// Relay a message and file the poster's callbacks against the id it comes back with.
///
/// The state lock is *not* held across the send. A messenger round trip is tens of
/// milliseconds at best, and the old code held the write lock — the one every other post
/// needs — for the whole of a subprocess spawn. Releasing it is only safe because callbacks
/// are now filed by message id rather than by "the last line of the file", so two posts may
/// interleave without stealing each other's rows.
async fn relay(
    state: &ServerLock,
    ns: Namespace,
    verified: Verified,
    mut msg: Outgoing,
) -> AppResult<MessageId> {
    msg.persona = verified.persona;

    let transport = state.read().await.channel(ns).transport.clone();
    let sent = transport.send(msg).await?;

    let mut st = state.write().await;
    for cb in verified.callbacks {
        st.channel_mut(ns).records.record(&sent.id, cb)?;
    }

    Ok(sent.id)
}

/// Where a rate-limited post goes: the thread whose context it was proved against.
///
/// A pseudonym is derived from a context, so a proof naming a context it cannot find is a
/// proof about a thread the server does not have. That is a client bug (it did not fetch the
/// contexts) and it is refused rather than posted into the void.
fn thread_for(
    st: &ServerState,
    ns: Namespace,
    verified: &Verified,
) -> AppResult<Option<MessageId>> {
    let Some(context) = &verified.context else {
        return Ok(None);
    };

    let entry = st
        .channel(ns)
        .contexts
        .by_context(context)
        .ok_or_else(|| AppError::NotFound(format!("no thread has context {context}")))?;

    // Signal has no threads, so it stores no ts and the message is posted to the group
    // unthreaded — which is what the as-a-service Signal deployment has always done.
    Ok(entry.ts.clone().map(MessageId))
}

// ---------------------------------------------------------------------------------------
// Signal
// ---------------------------------------------------------------------------------------

pub async fn signal_anon(
    State(state): State<ServerLock>,
    Json(input): Json<SignalPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Signal,
        Flavour::Anon,
        "anon_msg",
        input.group_id,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn signal_pseudo(
    State(state): State<ServerLock>,
    Json(input): Json<SignalPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Signal,
        Flavour::Pseudo,
        "pseudo_msg",
        input.group_id,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn signal_pseudo_rate(
    State(state): State<ServerLock>,
    Json(input): Json<SignalPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Signal,
        Flavour::PseudoRate,
        "rate_pseudo",
        input.group_id,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn signal_reply(
    State(state): State<ServerLock>,
    Json(input): Json<SignalReply>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Signal,
        Flavour::Anon,
        "anon_msg",
        input.group_id,
        input.message,
        input.proof,
        Some(MessageId::from(input.timestamp)),
    )
    .await
}

pub async fn signal_reply_pseudo(
    State(state): State<ServerLock>,
    Json(input): Json<SignalReply>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Signal,
        Flavour::Pseudo,
        "pseudo_msg",
        input.group_id,
        input.message,
        input.proof,
        Some(MessageId::from(input.timestamp)),
    )
    .await
}

/// Rate a message. No proof: a rating says nothing about who is rating.
///
/// It is *not* applied to the poster's object here — it is accumulated in the ledger, and
/// applied only when someone invokes the callback the poster committed to (`/api/reputation`).
/// That indirection is the point: the service cannot change a member's reputation without
/// using a token that member handed it in advance.
pub async fn signal_react(
    State(state): State<ServerLock>,
    Json(input): Json<SignalReact>,
) -> AppResult<Response> {
    react(
        state,
        Namespace::Signal,
        input.group_id,
        MessageId::from(input.timestamp),
        &input.emoji,
    )
    .await
}

/// Prove that two pseudonyms are the same member, without saying which member.
pub async fn signal_authorship(
    State(state): State<ServerLock>,
    Json(input): Json<SignalProofOnly>,
) -> AppResult<Response> {
    let (name1, name2) = {
        let st = state.read().await;
        let vk = st.keys.authorship_pred_verifying_key.clone();
        let inputs = verify_predicate(&vk, &input.proof, "author", "Cannot claim authorship")?;
        (persona::petname(inputs[1]), persona::petname(inputs[3]))
    };

    let mut body = String::from("CLAIMED AUTHORSHIP INITIATED\n\n");
    body.push_str(
        "This message proves that the following two pseudonyms belong to the same anonymous \
         user:\n\n",
    );
    body.push_str(&format!("• {name1}\n• {name2}\n\n"));
    body.push_str("This demonstrates authorship continuity without revealing identity.\n\n");

    send_plain(&state, Namespace::Signal, input.group_id, body).await?;
    bench::close_latency("author");
    Ok(ok())
}

/// Claim a badge under a pseudonym.
pub async fn signal_badges(
    State(state): State<ServerLock>,
    Json(input): Json<SignalProofOnly>,
) -> AppResult<Response> {
    let badge = {
        let st = state.read().await;
        let vk = st.keys.badge_pred_verifying_key.clone();
        let inputs = verify_predicate(&vk, &input.proof, "badge", "Cannot claim badge")?;
        inputs[1].to_string()
    };

    let mut body = String::from("CLAIMED BADGE INITIATED\n\n");
    body.push_str(
        "This message demonstrates that the following badge belongs to anonymous user:\n\n",
    );
    body.push_str(&badge);

    send_plain(&state, Namespace::Signal, input.group_id, body).await?;
    bench::close_latency("badge");
    Ok(ok())
}

// ---------------------------------------------------------------------------------------
// Slack
// ---------------------------------------------------------------------------------------

pub async fn slack_anon(
    State(state): State<ServerLock>,
    Json(input): Json<SlackPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Slack,
        Flavour::Anon,
        "anon_msg",
        input.channel,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn slack_pseudo(
    State(state): State<ServerLock>,
    Json(input): Json<SlackPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Slack,
        Flavour::Pseudo,
        "pseudo_msg",
        input.channel,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn slack_pseudo_rate(
    State(state): State<ServerLock>,
    Json(input): Json<SlackPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Slack,
        Flavour::PseudoRate,
        "rate_pseudo",
        input.channel,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn slack_react(
    State(state): State<ServerLock>,
    Json(input): Json<SlackReact>,
) -> AppResult<Response> {
    react(
        state,
        Namespace::Slack,
        input.channel,
        MessageId(input.timestamp),
        &input.emoji,
    )
    .await
}

/// Ask an admin for a badge. The request is a proof — that the member is unbanned, and that
/// they do not already hold a badge that contradicts this one — and it commits to a callback
/// the admin invokes to grant it.
pub async fn slack_request_badge(
    State(state): State<ServerLock>,
    Json(input): Json<SlackProofOnly>,
) -> AppResult<Response> {
    let (callbacks, index) = {
        let mut st = state.write().await;
        let vk = st.keys.badge_request_verifying_key.clone();

        let mut reader = decode(Kind::BadgeRequest, &input.proof)?;
        let exec: ExecutedMethod<F, Snark, Args, Cr, 1> = reader.pull()?;
        let inputs = pub_inputs(&mut reader, 2)?;
        let (index, claimed) = (inputs[0], inputs[1]);

        let current = epoch(&st.db);
        let callbacks = verify_and_store(
            &mut st.db,
            &vk,
            exec,
            BadgesArgs { i: index, claimed },
            current,
            INTERACTION,
        )
        .map_err(|_| {
            AppError::Rejected(
                "Cannot request new badge: proof failed. Check if you are banned or have a \
                 Student or Faculty badge (you cannot have both)."
                    .into(),
            )
        })?;

        (callbacks, field_to_string(index))
    };

    let transport = state.read().await.slack.transport.clone();
    let sent = transport
        .send(Outgoing::new(
            ConversationId(input.channel),
            "A new Badge has been requested... Waiting for Admin Review",
        ))
        .await?;

    let mut st = state.write().await;
    for cb in &callbacks {
        st.slack.records.record(&sent.id, cb.clone())?;
        st.badges.request(StoredBadge {
            i: index.parse().unwrap_or(0),
            claimed: badge_name(&index).to_string(),
            cb: cb.clone(),
            timestamp: sent.id.0.clone(),
        })?;
    }

    Ok(ok())
}

/// Show off a badge you hold, as an image, under a pseudonym.
pub async fn slack_claim_badge(
    State(state): State<ServerLock>,
    Json(input): Json<SlackClaimBadge>,
) -> AppResult<Response> {
    let index = {
        let st = state.read().await;
        let vk = st.keys.badge_pred_verifying_key.clone();
        let inputs = verify_predicate(&vk, &input.proof, "badge", "Cannot claim badge")?;
        field_to_string(inputs[0])
    };

    let mut caption = String::from(":label: CLAIMED BADGE INITIATED\n\n");
    caption.push_str("The following anonymous user holds the following badge:\n");
    caption.push_str(badge_name(&index));

    let transport = state.read().await.slack.transport.clone();
    let mut msg = Outgoing::new(ConversationId(input.channel), caption);
    msg.attachments.push(Attachment {
        filename: input.badge_name,
        content_type: "png".into(),
        bytes: input.badge_bytes,
    });

    transport.send(msg).await?;
    Ok(ok())
}

pub async fn slack_authorship(
    State(state): State<ServerLock>,
    Json(input): Json<SlackProofOnly>,
) -> AppResult<Response> {
    let (name1, name2) = {
        let st = state.read().await;
        let vk = st.keys.authorship_pred_verifying_key.clone();
        let inputs = verify_predicate(&vk, &input.proof, "author", "Cannot claim authorship")?;
        (persona::petname(inputs[1]), persona::petname(inputs[3]))
    };

    let mut body = String::from("CLAIMED AUTHORSHIP INITIATED\n\n");
    body.push_str(
        "This message proves that the following two pseudonyms belong to the same anonymous \
         user:\n\n",
    );
    body.push_str(&format!("1. {name1}\n2. {name2}\n\n"));
    body.push_str("This demonstrates authorship continuity without revealing identity.\n\n");

    send_plain(&state, Namespace::Slack, input.channel, body).await?;
    Ok(ok())
}

// ---------------------------------------------------------------------------------------
// The shared bodies
// ---------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn post(
    state: ServerLock,
    ns: Namespace,
    flavour: Flavour,
    label: &str,
    conversation: String,
    message: String,
    proof: Vec<u8>,
    reply_to: Option<MessageId>,
) -> AppResult<Response> {
    let (verified, thread) = {
        let mut st = state.write().await;
        let verified = verify_post(&mut st, flavour, &proof, label)?;
        let thread = thread_for(&st, ns, &verified)?;
        (verified, thread)
    };

    let mut msg = Outgoing::new(ConversationId(conversation), message);
    // An explicit reply target (this is a reply) wins over the thread a rate-limited post
    // belongs to; they are never both set.
    msg.reply_to = reply_to.or(thread);

    relay(&state, ns, verified, msg).await?;
    bench::close_latency(label);

    Ok(ok())
}

async fn react(
    state: ServerLock,
    ns: Namespace,
    conversation: String,
    target: MessageId,
    emoji: &str,
) -> AppResult<Response> {
    let emoji = emoji_for(emoji);
    let conversation = ConversationId(conversation);

    let transport = state.read().await.channel(ns).transport.clone();
    transport.react(&conversation, &target, emoji).await?;

    let delta = match crate::state::emoji_name(emoji) {
        "upvote" => 1,
        "downvote" => -1,
        other => {
            // Flags and ban suggestions are not ratings. They are a prompt for a human to
            // open a ban poll, and they change nobody's reputation on their own.
            tracing::info!("{other} reaction on {target} noted, no reputation change");
            0
        }
    };

    if delta != 0 {
        state
            .write()
            .await
            .channel_mut(ns)
            .records
            .rate(&target, delta)?;
    }

    Ok(ok())
}

/// Relay a message that carries no callback — an authorship or badge claim. The proof has
/// already been checked; there is nothing to file.
async fn send_plain(
    state: &ServerLock,
    ns: Namespace,
    conversation: String,
    body: String,
) -> AppResult<MessageId> {
    let transport = state.read().await.channel(ns).transport.clone();
    let sent = transport
        .send(Outgoing::new(ConversationId(conversation), body))
        .await?;
    Ok(sent.id)
}

/// Verify a standalone Groth16 predicate proof and hand back its public inputs.
///
/// Used by every claim that changes nothing: an authorship claim, a badge claim, a vote. The
/// member proves a statement about their object without touching the bulletin, so there is no
/// interaction to append and no callback to file.
pub fn verify_predicate(vk: &VK, proof: &[u8], label: &str, refusal: &str) -> AppResult<Vec<F>> {
    use ark_snark::SNARK;

    let mut reader = decode(Kind::Predicate, proof)?;
    let proof: <Snark as SNARK<F>>::Proof = reader.pull()?;
    let inputs: Vec<F> = reader.pull()?;

    let (verified, start, millis) = bench::time(|| Snark::verify(vk, &inputs, &proof));
    bench::verified(label, start, millis);

    match verified {
        Ok(true) => Ok(inputs),
        Ok(false) | Err(_) => Err(AppError::Rejected(format!(
            "{refusal}: proof failed. Check if you are banned."
        ))),
    }
}

/// Public inputs, checked for length before anything indexes into them.
///
/// The old code read `pub_inputs[1]` straight off the wire, so a proof carrying a shorter
/// vector than its route expected panicked the handler — a remote crash from a member who
/// simply sent the wrong record to the wrong route.
fn pub_inputs(reader: &mut personas_wire::Reader, expected: usize) -> AppResult<Vec<F>> {
    let inputs: Vec<F> = reader.pull()?;

    if inputs.len() < expected {
        return Err(AppError::BadRequest(format!(
            "this proof needs {expected} public inputs, got {}",
            inputs.len()
        )));
    }

    Ok(inputs)
}

/// A field element as the decimal string the contexts and badge logs are keyed by.
///
/// The same encoding the client writes when it stores a context, and the same one the badge
/// log keys on: `into_bigint().to_string()`, canonical decimal.
pub fn field_to_string(f: F) -> String {
    f.into_bigint().to_string()
}
