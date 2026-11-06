//! A sparse Merkle tree: every leaf has a fixed slot, and absent subtrees cost nothing.
//!
//! The object bulletin needs a root that depends only on the SET of objects, so that
//! replicas receiving records in different orders agree. Giving each object the slot its
//! own hash points at does that with one path update per insert, instead of re-hashing the
//! whole set. The tree shares unchanged subtrees between copies, so cloning it, which the
//! replica does for every checkpoint, is constant time.

use std::sync::Arc;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;

use super::tree::{MerklePath, empty_subtree_hashes, hash_pair};

#[derive(Debug)]
struct Node<F> {
    hash: F,
    left: Option<Arc<Node<F>>>,
    right: Option<Arc<Node<F>>>,
}

/// A fixed-height sparse Poseidon Merkle tree, compatible with [`MerklePath`] and its
/// in-circuit check.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree<F: PrimeField + Absorb, const HEIGHT: usize> {
    /// `zeros[l]` = hash of an empty subtree rooted at level `l`. Length `HEIGHT + 1`.
    zeros: Arc<Vec<F>>,
    root: Option<Arc<Node<F>>>,
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> Default for SparseMerkleTree<F, HEIGHT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> SparseMerkleTree<F, HEIGHT> {
    pub fn new() -> Self {
        assert!(
            (1..64).contains(&HEIGHT),
            "a slot is a u64, so HEIGHT must be between 1 and 63"
        );
        Self {
            zeros: Arc::new(empty_subtree_hashes::<F>(HEIGHT)),
            root: None,
        }
    }

    pub fn root(&self) -> F {
        self.root.as_ref().map_or(self.zeros[HEIGHT], |n| n.hash)
    }

    fn hash_at(&self, node: Option<&Arc<Node<F>>>, level: usize) -> F {
        node.map_or(self.zeros[level], |n| n.hash)
    }

    /// Set the leaf at `slot`, re-hashing only its path.
    pub fn set(&mut self, slot: u64, leaf: F) {
        self.root = Some(self.updated(self.root.as_ref(), HEIGHT, slot, leaf));
    }

    fn updated(
        &self,
        node: Option<&Arc<Node<F>>>,
        level: usize,
        slot: u64,
        leaf: F,
    ) -> Arc<Node<F>> {
        if level == 0 {
            return Arc::new(Node {
                hash: leaf,
                left: None,
                right: None,
            });
        }
        let left = node.and_then(|n| n.left.clone());
        let right = node.and_then(|n| n.right.clone());
        let (left, right) = if slot >> (level - 1) & 1 == 0 {
            (Some(self.updated(left.as_ref(), level - 1, slot, leaf)), right)
        } else {
            let updated = self.updated(right.as_ref(), level - 1, slot, leaf);
            (left, Some(updated))
        };
        Arc::new(Node {
            hash: hash_pair(
                self.hash_at(left.as_ref(), level - 1),
                self.hash_at(right.as_ref(), level - 1),
            ),
            left,
            right,
        })
    }

    /// The leaf at `slot`, or `None` if it was never set.
    pub fn leaf(&self, slot: u64) -> Option<F> {
        let mut node = self.root.as_ref()?;
        for level in (0..HEIGHT).rev() {
            let child = if slot >> level & 1 == 0 {
                &node.left
            } else {
                &node.right
            };
            node = child.as_ref()?;
        }
        Some(node.hash)
    }

    /// The path from `slot` to the root, siblings bottom to top.
    pub fn path(&self, slot: u64) -> MerklePath<F, HEIGHT> {
        let mut siblings = vec![F::zero(); HEIGHT];
        let mut node = self.root.as_ref();
        for level in (0..HEIGHT).rev() {
            let (next, sibling) = match node {
                Some(n) if slot >> level & 1 == 0 => (n.left.as_ref(), n.right.as_ref()),
                Some(n) => (n.right.as_ref(), n.left.as_ref()),
                None => (None, None),
            };
            siblings[level] = self.hash_at(sibling, level);
            node = next;
        }
        MerklePath {
            leaf_index: slot,
            siblings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as F;

    type Tree = SparseMerkleTree<F, 8>;

    #[test]
    fn a_path_proves_its_leaf_against_the_root() {
        let mut t = Tree::new();
        for (slot, leaf) in [(3, 30), (200, 7), (4, 1), (255, 9)] {
            t.set(slot, F::from(leaf));
        }
        for (slot, leaf) in [(3, 30), (200, 7), (4, 1), (255, 9)] {
            assert_eq!(t.path(slot).compute_root(F::from(leaf)), t.root());
            assert_eq!(t.leaf(slot), Some(F::from(leaf)));
        }
        assert_eq!(t.leaf(5), None);
    }

    #[test]
    fn the_root_does_not_depend_on_insertion_order() {
        let (mut a, mut b) = (Tree::new(), Tree::new());
        for (slot, leaf) in [(1, 10), (2, 20), (130, 30)] {
            a.set(slot, F::from(leaf));
        }
        for (slot, leaf) in [(130, 30), (1, 10), (2, 20)] {
            b.set(slot, F::from(leaf));
        }
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn a_clone_is_unaffected_by_later_inserts() {
        let mut a = Tree::new();
        a.set(1, F::from(10));
        let before = a.clone();
        let root = a.root();
        a.set(2, F::from(20));
        assert_eq!(before.root(), root);
        assert_ne!(a.root(), root);
    }

    #[test]
    fn an_empty_tree_has_the_all_zeros_root() {
        let t = Tree::new();
        assert_eq!(t.path(9).compute_root(F::from(0)), t.root());
    }
}
