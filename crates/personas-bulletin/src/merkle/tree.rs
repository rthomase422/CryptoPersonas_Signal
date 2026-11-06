//! A fixed-height, append-only (incremental) binary Merkle tree over Poseidon.
//!
//! This is the native (out-of-circuit) half of the serverless object bulletin.
//! It is deliberately the *same* hash the rest of the system commits with —
//! [`Poseidon<2>`] as a 2-to-1 compression function — so a root computed here
//! is the root the in-circuit gadget ([`super::gadget`]) recomputes, and both
//! match what zk-callbacks hashes elsewhere.
//!
//! # Structure
//!
//! The tree has a fixed `HEIGHT`, giving `2^HEIGHT` leaf slots filled
//! left-to-right. Empty slots hash as a fixed sentinel (`F::zero`), and an
//! empty subtree of level `l` has the precomputed hash `zeros[l]`
//! (`zeros[0] = 0`, `zeros[l+1] = H(zeros[l], zeros[l])`). This is the standard
//! Tornado/Semaphore incremental-tree construction: an append touches only the
//! `HEIGHT` nodes on the new leaf's path, so both append and witness lookup are
//! `O(HEIGHT)`.
//!
//! # Why append-only is sound with a *buffered* root (the O10 lesson)
//!
//! Membership of an append-only set is **monotone**: once a leaf is in the tree
//! it stays in, and no later append can evict it. So a witness against a
//! slightly stale root is still a valid witness against a newer root's history
//! — a replica may safely accept membership proofs against any recent root it
//! has itself computed (a ring buffer of the last K roots). This is the exact
//! opposite of callback *non*membership, which is anti-monotone and must pin the
//! current epoch's root only — see [`super::callback`]. Rewind is blocked not by
//! the root but by the nullifier set (`has_never_received_nul`).

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use ark_crypto_primitives::crh::{CRHScheme, poseidon::CRH};
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};

/// The value stored in an unfilled leaf slot.
///
/// A real object commitment is a Poseidon image, so a collision with this
/// sentinel is cryptographically negligible; nonetheless the tree never treats
/// a zero leaf as "present" (membership is decided by the index map, not by
/// scanning for a value), so an object that happened to commit to zero would
/// still work.
pub fn empty_leaf<F: PrimeField>() -> F {
    F::zero()
}

/// Hash two field elements into their parent with the system Poseidon.
///
/// This is the single definition of an internal node; the gadget mirrors it
/// with [`Poseidon::hash_in_zk`] over the same two-element input in the same
/// (left, right) order.
pub fn hash_pair<F: PrimeField + Absorb>(left: F, right: F) -> F {
    poseidon2(&[left, right])
}

/// The system Poseidon, `zk_callbacks`' `Poseidon<2>::hash`, with its parameters
/// generated once instead of on every call.
///
/// `Poseidon<2>::hash` re-derives the round constants and MDS matrix (a Grain LFSR run)
/// for every single hash. That dominated the replica's cost: a rebuild of a height-32
/// tree is thousands of hashes, so one incoming post cost seconds on the UI thread.
/// The parameters are a pure function of the field, so caching them changes nothing
/// about the output; `tests::cached_poseidon_matches_the_library` pins that.
pub(crate) fn poseidon2<F: PrimeField + Absorb>(data: &[F]) -> F {
    CRH::evaluate(poseidon2_params::<F>().as_ref(), data).expect("poseidon evaluate")
}

type ParamsCache = Mutex<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>;

fn poseidon2_params<F: PrimeField + Absorb>() -> Arc<PoseidonConfig<F>> {
    static CACHE: OnceLock<ParamsCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().expect("poseidon params cache poisoned");
    let entry = cache
        .entry(TypeId::of::<F>())
        .or_insert_with(|| Arc::new(rate2_params::<F>()));
    Arc::clone(entry)
        .downcast::<PoseidonConfig<F>>()
        .expect("cache is keyed by field type")
}

/// Exactly `zk_callbacks::util::gen_poseidon_params(2, false)` (crate-private there):
/// rate 2, alpha 17, 8 full rounds, 31 partial rounds, capacity 1.
fn rate2_params<F: PrimeField>() -> PoseidonConfig<F> {
    let (rate, alpha, full_rounds, partial_rounds, skip_matrices) = (2, 17, 8, 31, 0);
    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds,
        partial_rounds,
        skip_matrices,
    );
    PoseidonConfig {
        full_rounds: full_rounds as usize,
        partial_rounds: partial_rounds as usize,
        alpha,
        ark,
        mds,
        rate,
        capacity: 1,
    }
}

/// Precompute `zeros[0..=HEIGHT]`, the hash of an empty subtree at each level.
pub(crate) fn empty_subtree_hashes<F: PrimeField + Absorb>(height: usize) -> Vec<F> {
    let mut zeros = Vec::with_capacity(height + 1);
    zeros.push(empty_leaf::<F>());
    for l in 0..height {
        let z = zeros[l];
        zeros.push(hash_pair(z, z));
    }
    zeros
}

/// A membership witness: the index of a leaf and the sibling hash at each level
/// on the path from that leaf to the root.
///
/// `siblings` is always length `HEIGHT`; `leaf_index`'s low `HEIGHT` bits select
/// left/right at each level (bit `l` set ⇒ the current node is the *right*
/// child at level `l`). The [`Default`] impl deliberately yields a full
/// `HEIGHT`-length sibling vector of zeros: the circuit's shape (how many hash
/// rounds it performs) is fixed at key-generation time from the *default*
/// witness, so a short default would bake a wrong-sized circuit.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerklePath<F: PrimeField, const HEIGHT: usize> {
    /// The leaf's position (0-based, left to right).
    pub leaf_index: u64,
    /// Sibling hash at each level, bottom (leaf's sibling) to top. Length `HEIGHT`.
    pub siblings: Vec<F>,
}

impl<F: PrimeField, const HEIGHT: usize> Default for MerklePath<F, HEIGHT> {
    fn default() -> Self {
        Self {
            leaf_index: 0,
            siblings: vec![F::zero(); HEIGHT],
        }
    }
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> MerklePath<F, HEIGHT> {
    /// Recompute the root this path attests to, from the committed `leaf`.
    ///
    /// The native counterpart of [`super::gadget::enforce_merkle_membership`];
    /// the two must agree bit-for-bit. A caller checks membership by comparing
    /// the result against a known root.
    pub fn compute_root(&self, leaf: F) -> F {
        let mut cur = leaf;
        for (l, sib) in self.siblings.iter().enumerate().take(HEIGHT) {
            let is_right = (self.leaf_index >> l) & 1 == 1;
            let (left, right) = if is_right { (*sib, cur) } else { (cur, *sib) };
            cur = hash_pair(left, right);
        }
        cur
    }
}

/// A fixed-height, append-only Poseidon Merkle tree.
///
/// Leaves are appended left to right; the root and any leaf's [`MerklePath`] are
/// available in `O(HEIGHT)`. The tree is `Clone`/`Default` and carries no secret
/// state (unlike the signature-based stores it replaces, there are no keys).
#[derive(Clone, Debug)]
pub struct IncrementalMerkleTree<F: PrimeField + Absorb, const HEIGHT: usize> {
    /// `zeros[l]` = hash of an empty subtree rooted at level `l`. Length `HEIGHT+1`.
    zeros: Vec<F>,
    /// Materialized nodes, densely filled left-to-right. `levels[0]` are leaves;
    /// `levels[HEIGHT]` holds (at most) the single root. A position absent from a
    /// level is implicitly `zeros[level]`.
    levels: Vec<Vec<F>>,
    /// Number of appended leaves.
    count: usize,
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> Default for IncrementalMerkleTree<F, HEIGHT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> IncrementalMerkleTree<F, HEIGHT> {
    /// An empty tree of the fixed height.
    pub fn new() -> Self {
        assert!(HEIGHT >= 1, "Merkle tree height must be at least 1");
        assert!(
            HEIGHT < 64,
            "leaf_index is a u64; HEIGHT must be < 64 to address all slots"
        );
        Self {
            zeros: empty_subtree_hashes::<F>(HEIGHT),
            levels: vec![Vec::new(); HEIGHT + 1],
            count: 0,
        }
    }

    /// The number of leaves appended so far.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether no leaves have been appended.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Maximum number of leaves this height can hold (`2^HEIGHT`), saturating.
    pub fn capacity(&self) -> u64 {
        1u64.checked_shl(HEIGHT as u32).unwrap_or(u64::MAX)
    }

    /// The materialized-or-empty hash of the node at `(level, index)`.
    fn node(&self, level: usize, index: usize) -> F {
        self.levels[level]
            .get(index)
            .copied()
            .unwrap_or(self.zeros[level])
    }

    /// The current root.
    pub fn root(&self) -> F {
        self.node(HEIGHT, 0)
    }

    /// Append a leaf, returning its index. Recomputes only the `HEIGHT` nodes on
    /// the new leaf's path.
    ///
    /// Panics if the tree is already full — a full serverless object tree means
    /// the group has hit `2^HEIGHT` registrations, a configuration error, not a
    /// runtime condition to paper over.
    pub fn append(&mut self, leaf: F) -> usize {
        assert!(
            (self.count as u64) < self.capacity(),
            "Merkle tree of height {HEIGHT} is full ({} leaves)",
            self.count
        );
        let idx = self.count;
        self.set(0, idx, leaf);
        self.count += 1;

        // Walk to the root, recomputing each parent from its (possibly empty) children.
        let mut pos = idx;
        for l in 0..HEIGHT {
            let left = self.node(l, pos & !1);
            let right = self.node(l, pos | 1);
            let parent = hash_pair(left, right);
            self.set(l + 1, pos >> 1, parent);
            pos >>= 1;
        }
        idx
    }

    /// The tree that appending `leaves` in order would give, built level by level.
    ///
    /// Appending one at a time re-hashes the new leaf's whole path, `HEIGHT` hashes per
    /// leaf. But once every leaf is in, each materialized node is just the hash of its two
    /// children (an absent right child being `zeros[level]`) — so hashing each level from
    /// the one below gives exactly the same nodes with about two hashes per leaf
    /// (`tests::from_leaves_matches_appending` pins the equality).
    pub fn from_leaves(leaves: impl IntoIterator<Item = F>) -> Self {
        let mut tree = Self::new();
        let base: Vec<F> = leaves.into_iter().collect();
        assert!(
            (base.len() as u64) <= tree.capacity(),
            "Merkle tree of height {HEIGHT} cannot hold {} leaves",
            base.len()
        );
        tree.count = base.len();
        if base.is_empty() {
            return tree;
        }
        tree.levels[0] = base;
        for l in 0..HEIGHT {
            let below = &tree.levels[l];
            let parents: Vec<F> = below
                .chunks(2)
                .map(|pair| hash_pair(pair[0], pair.get(1).copied().unwrap_or(tree.zeros[l])))
                .collect();
            tree.levels[l + 1] = parents;
        }
        tree
    }

    /// Write `value` at `(level, index)`, extending the dense level as needed.
    ///
    /// Appends fill positions left-to-right without gaps, so `index` is always
    /// either the next free slot or the current rightmost slot.
    fn set(&mut self, level: usize, index: usize, value: F) {
        let lvl = &mut self.levels[level];
        match index.cmp(&lvl.len()) {
            std::cmp::Ordering::Less => lvl[index] = value,
            std::cmp::Ordering::Equal => lvl.push(value),
            std::cmp::Ordering::Greater => {
                // Never happens for left-to-right appends, but keep the invariant
                // total rather than silently corrupting the tree.
                lvl.resize(index, self.zeros[level]);
                lvl.push(value);
            }
        }
    }

    /// The membership witness for the leaf at `index`, or `None` if out of range.
    pub fn path(&self, index: usize) -> Option<MerklePath<F, HEIGHT>> {
        if index >= self.count {
            return None;
        }
        let mut siblings = Vec::with_capacity(HEIGHT);
        let mut pos = index;
        for l in 0..HEIGHT {
            siblings.push(self.node(l, pos ^ 1));
            pos >>= 1;
        }
        Some(MerklePath {
            leaf_index: index as u64,
            siblings,
        })
    }

    /// The leaf value at `index`, or `None` if out of range.
    pub fn leaf(&self, index: usize) -> Option<F> {
        self.levels[0].get(index).copied()
    }

    /// The index of the first leaf equal to `leaf`, or `None`.
    ///
    /// Object commitments carry commitment randomness, so in practice they are
    /// unique; on the astronomically unlikely event of a collision this returns
    /// the earliest, which is a valid member either way.
    pub fn position(&self, leaf: F) -> Option<usize> {
        self.levels[0][..self.count].iter().position(|c| *c == leaf)
    }
}

#[cfg(test)]
mod from_leaves_tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn from_leaves_matches_appending() {
        for n in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 64, 100] {
            let leaves: Vec<Fr> = (0..n).map(|i| Fr::from(1000 + i as u64 * 7)).collect();
            let mut appended = IncrementalMerkleTree::<Fr, 8>::new();
            for leaf in &leaves {
                appended.append(*leaf);
            }
            let built = IncrementalMerkleTree::<Fr, 8>::from_leaves(leaves.iter().copied());
            assert_eq!(built.root(), appended.root(), "root, n = {n}");
            assert_eq!(built.len(), appended.len(), "len, n = {n}");
            assert_eq!(built.levels, appended.levels, "every node, n = {n}");
            for i in 0..n {
                assert_eq!(built.path(i), appended.path(i), "path {i}, n = {n}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as F;

    const H: usize = 6;

    /// The cached Poseidon must be bit-for-bit the library's: every replica's roots,
    /// and every proof's public inputs, depend on it.
    #[test]
    fn cached_poseidon_matches_the_library() {
        use zk_callbacks::{crypto::hash::HasherZK, impls::hash::Poseidon};
        let inputs: Vec<Vec<F>> = vec![
            vec![F::from(0u64)],
            vec![F::from(7u64)],
            vec![F::from(1u64), F::from(2u64)],
            vec![F::from(u64::MAX), -F::from(3u64)],
            vec![F::from(5u64), F::from(6u64), F::from(7u64)],
        ];
        for data in inputs {
            assert_eq!(
                poseidon2(&data),
                <Poseidon<2>>::hash(&data),
                "input {data:?}"
            );
        }
        let (a, b) = (F::from(11u64), F::from(13u64));
        assert_eq!(hash_pair(a, b), <Poseidon<2>>::hash(&[a, b]));
    }

    /// Every appended leaf produces a path that recomputes the current root.
    #[test]
    fn paths_recompute_the_root() {
        let mut tree = IncrementalMerkleTree::<F, H>::new();
        let leaves: Vec<F> = (1u64..=20).map(F::from).collect();
        for &l in &leaves {
            tree.append(l);
        }
        let root = tree.root();
        for (i, &l) in leaves.iter().enumerate() {
            let path = tree.path(i).expect("leaf has a path");
            assert_eq!(path.compute_root(l), root, "leaf {i} path must reach root");
        }
    }

    /// A stale path (taken before later appends) reaches the *old* root, not the
    /// new one — the property that makes buffered-root membership sound.
    #[test]
    fn appends_change_the_root_but_old_paths_reach_old_roots() {
        let mut tree = IncrementalMerkleTree::<F, H>::new();
        tree.append(F::from(10));
        let root0 = tree.root();
        let path0 = tree.path(0).unwrap();
        assert_eq!(path0.compute_root(F::from(10)), root0);

        tree.append(F::from(11));
        let root1 = tree.root();
        assert_ne!(root0, root1, "an append must move the root");
        // The leaf-0 path re-fetched after the append reaches the new root...
        let path0b = tree.path(0).unwrap();
        assert_eq!(path0b.compute_root(F::from(10)), root1);
        // ...while the pre-append path still reaches the old root (monotone history).
        assert_eq!(path0.compute_root(F::from(10)), root0);
    }

    /// A wrong leaf, wrong sibling, or wrong index bit all fail to reach the root.
    #[test]
    fn tampering_breaks_the_path() {
        let mut tree = IncrementalMerkleTree::<F, H>::new();
        for l in 1u64..=8 {
            tree.append(F::from(l));
        }
        let root = tree.root();
        let path = tree.path(3).unwrap();
        let leaf = F::from(4);
        assert_eq!(path.compute_root(leaf), root);

        // Wrong leaf.
        assert_ne!(path.compute_root(F::from(999)), root);
        // Wrong sibling.
        let mut bad = path.clone();
        bad.siblings[0] += F::from(1);
        assert_ne!(bad.compute_root(leaf), root);
        // Wrong index bit (claim leaf 3 sits at position 2).
        let mut bad_idx = path.clone();
        bad_idx.leaf_index = 2;
        assert_ne!(bad_idx.compute_root(leaf), root);
    }

    /// The empty-tree root is the top empty-subtree hash, and the first append
    /// leaves every other slot empty.
    #[test]
    fn empty_root_is_zeros_top() {
        let tree = IncrementalMerkleTree::<F, H>::new();
        let zeros = empty_subtree_hashes::<F>(H);
        assert_eq!(tree.root(), zeros[H]);
        assert!(tree.is_empty());
    }

    /// `Default` witness has a full-height sibling vector so the circuit shape is
    /// fixed regardless of which real leaf is later proven.
    #[test]
    fn default_path_is_full_height() {
        let p = MerklePath::<F, H>::default();
        assert_eq!(p.siblings.len(), H);
    }
}
