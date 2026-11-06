//! The serverless Merkle bulletin (workstream **d1**).
//!
//! In *service* mode the bulletin is trusted: a single server signs every entry
//! and clients prove knowledge of a signature ([`http::BulNet`] over
//! zk-callbacks' `SigObjStore`/`CallbackStore`). Serverless mode has no signer,
//! so membership must be proven against a **Merkle root** that every replica
//! recomputes from the same ordered log. This module builds those trees against
//! zk-callbacks' public bulletin traits — it does **not** fork the upstream
//! `decentralized::ds` stub, which is empty.
//!
//! [`http::BulNet`]: crate::http::BulNet
//!
//! # Layout
//!
//! - [`tree`] — the fixed-height append-only Poseidon Merkle tree and its native
//!   [`MerklePath`] witness (the object bulletin's backing store).
//! - [`gadget`] — the in-circuit path-verification gadget
//!   ([`enforce_merkle_membership`]) and the allocated [`MerklePathVar`].
//! - [`obj`] — [`MerkleObjStore`], implementing zk-callbacks'
//!   `PublicUserBul`/`UserBul`/`JoinableBulletin` for the object tree (d1a).
//! - [`callback`] — [`MerkleCallbackStore`], implementing `PublicCallbackBul`/
//!   `CallbackBul` via a called-ticket membership tree plus a sorted-range
//!   nonmembership tree that pins the current epoch's root (d1b — the O10 fix).
//!
//! # The O10 lesson, encoded structurally
//!
//! The scan circuit never binds the callback epoch, so a *signed* nonmembership
//! range can be replayed after a ban (FINDINGS O10). The Merkle store closes
//! this by construction: public data is a **root**, not a stable key, so it
//! cannot be a circuit constant and instead becomes a **public input** each
//! replica pins against a root it computed itself — a stale witness has no
//! current root to hash up to. Membership (object tree) is monotone and safe
//! against a *buffered* recent root; nonmembership (callback tree, d1b) is
//! anti-monotone and must pin the current epoch's root exactly. See
//! [`tree`] and `docs/SERVERLESS_PROTOCOL.md`.
//!
//! [`enforce_merkle_membership`]: gadget::enforce_merkle_membership
//! [`MerklePath`]: tree::MerklePath
//! [`MerklePathVar`]: gadget::MerklePathVar
//! [`MerkleObjStore`]: obj::MerkleObjStore

pub mod callback;
pub mod gadget;
pub mod obj;
pub mod params;
pub mod sparse;
pub mod tree;

pub use callback::{
    MerkleCallbackStore, RangeWitness, RangeWitnessVar, enforce_range_nonmembership,
};
pub use gadget::{MerklePathVar, enforce_merkle_membership};
pub use obj::{DEFAULT_OBJ_HEIGHT, MerkleObjStore};
pub use params::{MERKLE_BULLETIN_MODE, MerkleCStore, MerkleOStore, generate_merkle_server_keys};
pub use tree::{IncrementalMerkleTree, MerklePath};
