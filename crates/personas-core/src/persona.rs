//! Persona derivation and rendering.
//!
//! A *pseudonym* is a field element `claimed = H(sk, context)` (see
//! [`circuits::pseudonym_pred`](crate::circuits::pseudonym_pred)). Everything a human
//! sees — the two-word petname on a message — is derived deterministically from that
//! field element here, so client and server always agree on what to call a persona
//! without either learning `sk`.

use ark_ff::{BigInteger, BigInteger256, PrimeField};
use petname::{Generator, Petnames};
use rand::{SeedableRng, rngs::StdRng};
use std::str::FromStr;
use zk_callbacks::crypto::hash::HasherZK;

use crate::{F, H};

/// Shown when a pseudonym cannot be rendered (an empty petname word list).
pub const ANONYMOUS: &str = "anonymous user";

/// The pseudonym for `context` under secret key `sk`: `H(sk, context)`.
///
/// This is the same hash the `pseudonym_pred` circuit enforces, so a persona derived
/// here is exactly the one a proof will bind to.
pub fn pseudonym(sk: &F, context: &F) -> F {
    H::hash(&[*sk, *context])
}

/// The `i`-th rate-limited pseudonym for `context` under secret key `sk`: `H(sk, context, i)`.
///
/// Matches `standard_pseudo_rate_predicate`; the replica allows `i < RATE_LIMITED_PERSONAS_PER_CONTEXT` (3).
pub fn pseudonym_rate(sk: &F, context: &F, i: &F) -> F {
    H::hash(&[*sk, *context, *i])
}

/// A member's public key: what `join_pred` proves its `pk` input is. See
/// [`member_pk_tag`](crate::circuits::member_pk_tag).
pub fn member_pk(sk: &F) -> F {
    let tag = crate::circuits::member_pk_tag();
    H::hash(&[*sk, tag, tag])
}

/// The human-readable name for a pseudonym: two petname words, seeded by `claimed`.
///
/// Deterministic in `claimed` alone — the client and the server derive the same name
/// independently, and observers can link two messages by the same persona (which is
/// the point) without linking either to a user.
pub fn petname(claimed: F) -> String {
    let bytes = claimed.into_bigint().to_bytes_le();

    let mut seed = [0u8; 32];
    let len = bytes.len().min(32);
    seed[..len].copy_from_slice(&bytes[..len]);

    let mut rng = StdRng::from_seed(seed);
    Petnames::default()
        .generate(&mut rng, 2, " ")
        .unwrap_or_else(|| ANONYMOUS.to_string())
}

/// [`petname`] for a pseudonym in decimal-string form, as it is stored in the
/// pseudonym log and carried on the wire. Returns [`ANONYMOUS`] if `claimed` is not a
/// well-formed field element.
pub fn petname_from_str(claimed: &str) -> String {
    match field_from_str(claimed) {
        Some(f) => petname(f),
        None => ANONYMOUS.to_string(),
    }
}

/// Parse a field element from its decimal (`BigInteger256`) string form.
pub fn field_from_str(s: &str) -> Option<F> {
    F::from_bigint(BigInteger256::from_str(s).ok()?)
}
