//! Merkle-mode key generation (d1d).
//!
//! The serverless (Merkle) bulletin proves membership against a **root**, which
//! changes on every append and so cannot be a circuit constant. Every keygen
//! here therefore differs from the centralized [`personas_core::params`] path in
//! exactly two places:
//!
//! 1. **Object membership** is generated with `memb_data = None` (vs. the central
//!    `Some(pubkey)`), which sets `bul_memb_is_const = false` in the circuit
//!    ([interaction.rs `generate_keys`]) — the object root becomes a **public
//!    input** the verifier supplies per proof.
//! 2. **Scan callback data** is built with `is_memb_data_const = false` and
//!    `is_nmemb_data_const = false` (vs. the central `true`/`true` in
//!    `get_extra_pubdata_for_scan`), so the callback membership and nonmembership
//!    **roots** are public inputs too — this is the structural O10 fix (see
//!    [`super::callback`]).
//!
//! Everything else — the interactions, predicates, the `MsgUser` object, the
//! `Poseidon<2>` hash — is shared verbatim with the centralized circuits via
//! `personas_core`. The circuits are generic over the bulletin store, so a
//! Merkle store is a drop-in substitution at the type level.
//!
//! Nova folding keys for Merkle mode are deferred: serverless defaults folding
//! **off** (locked decision), so only the Groth16 key sets are built here.
//!
//! [interaction.rs `generate_keys`]: zk_callbacks::generic::interaction

use std::path::Path;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use personas_core::circuits::{
    BadgesArgs, BadgesArgsVar, MsgUser, NUM_SCANS_PER_FOLD, PseudonymArgs, PseudonymArgsPair,
    PseudonymArgsPairVar, PseudonymArgsRate, PseudonymArgsVar, PubScan, ScanInt, authorship_pred,
    badge_pred, get_badge_request_interaction, get_callbacks, get_scan_interaction,
    get_standard_interaction, get_standard_pseudo_interaction,
    JoinArgs, JoinArgsVar, ResetArgs, ResetArgsVar, get_standard_pseudo_rate_interaction,
    join_pred, not_banned_pred, pseudonym_pred,
};
use personas_core::params::ServerKeys;
use personas_core::{Cr, F, H, PK, Snark, VK};
use zk_callbacks::generic::interaction::{
    generate_keys_for_statement, generate_keys_for_statement_in,
};
use zk_callbacks::generic::object::Time;

use super::callback::{DEFAULT_CB_MEMB_HEIGHT, DEFAULT_CB_NMEMB_HEIGHT, MerkleCallbackStore};
use super::obj::{DEFAULT_OBJ_HEIGHT, MerkleObjStore};

/// The object bulletin the production Merkle keys are generated for.
pub type MerkleOStore = MerkleObjStore<F, DEFAULT_OBJ_HEIGHT>;
/// The callback bulletin the production Merkle keys are generated for.
pub type MerkleCStore = MerkleCallbackStore<F, DEFAULT_CB_MEMB_HEIGHT, DEFAULT_CB_NMEMB_HEIGHT>;

/// Bulletin-mode tag for the params disk cache.
///
/// Merkle keys are structurally different from the `central-grschnorr` keys (the
/// roots are extra public inputs), so they must never share a cache entry. When
/// the replica/server caches these, it keys on this string in place of
/// [`personas_core::params::BULLETIN_MODE`].
pub const MERKLE_BULLETIN_MODE: &str = "serverless-merkle";

/// Cache filename for the Merkle-mode Groth16 key bundle.
const MERKLE_KEYS_FILE: &str = "merkle_groth16_keys.bin";

/// Load the Merkle-mode [`ServerKeys`] from `data_dir`'s params cache, generating and
/// caching them on first run.
///
/// This wires the [`MERKLE_BULLETIN_MODE`] cache that d1 defined but left unused (its
/// review note listed disk-cache integration as deferred): d4's messenger needs a
/// warm boot to be usable, and the merkle keys depend only on the circuits (not on
/// any store's contents), so the mode-tagged subdir is the whole cache key. A
/// dependency-rev bump changes the circuits and so must be paired with clearing this
/// directory — the same discipline [`personas_core::params::DEP_REVS`] enforces for
/// the centralized keys. Keys are written uncompressed (`Compress::No`), matching the
/// centralized artifact cache: proving keys are read once per boot and decompression
/// would cost a modular sqrt per curve point for no benefit.
pub fn ensure_merkle_keys(data_dir: &Path) -> std::io::Result<ServerKeys> {
    let dir = data_dir.join("params").join(MERKLE_BULLETIN_MODE);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(MERKLE_KEYS_FILE);

    let decode = |bytes: &[u8]| {
        ServerKeys::deserialize_with_mode(bytes, Compress::No, Validate::No)
            .map_err(std::io::Error::other)
    };
    let generate = || {
        tracing::info!(
            "generating Merkle-mode keys into {} (first run is slow)",
            dir.display()
        );
        let mut rng = ark_std::rand::rngs::OsRng;
        let keys = generate_merkle_server_keys(&mut rng, &MerkleCStore::new());
        let mut buf = Vec::new();
        keys.serialize_with_mode(&mut buf, Compress::No)
            .map_err(std::io::Error::other)?;
        Ok((keys, buf))
    };
    load_or_publish(&path, decode, generate)
}

/// Load the shared artifact at `path`, or generate and publish it, such that every
/// caller sharing `path` — threads, processes, or containers on one volume — ends up
/// with the **same** value.
///
/// Keygen is randomized (OsRng), so two engines that each generate on an empty cache
/// hold different keys and reject each other's proofs (FINDINGS F8). The old code
/// wrote a fixed `….tmp` name and `rename`d it into place, which let the last writer
/// silently replace the file while every earlier writer kept its own keys in memory.
///
/// Two layers, mirroring `ensurePhantomMaterial` in the Signal-Desktop preload:
///
/// 1. An advisory lock on `<path>.lock` serializes generators, and the cache is
///    re-read once the lock is held — so a caller that waited adopts the winner's
///    file instead of spending minutes on a keygen it would throw away. This is an
///    optimization only: if the lock is unavailable (e.g. a filesystem without
///    `flock`), we proceed without it.
/// 2. [`publish_or_adopt`] — the actual correctness guarantee — publishes with an
///    exclusive hard link and adopts the on-disk file if someone beat us to it.
fn load_or_publish<T>(
    path: &Path,
    decode: impl Fn(&[u8]) -> std::io::Result<T>,
    generate: impl FnOnce() -> std::io::Result<(T, Vec<u8>)>,
) -> std::io::Result<T> {
    enum Cache<T> {
        Hit(T),
        Missing,
        Corrupt,
    }
    let try_load = |path: &Path| -> std::io::Result<Cache<T>> {
        match std::fs::read(path) {
            Ok(bytes) => match decode(&bytes) {
                Ok(v) => {
                    tracing::info!("loaded Merkle-mode keys from cache {}", path.display());
                    Ok(Cache::Hit(v))
                }
                Err(e) => {
                    tracing::warn!("key cache at {} is unreadable ({e})", path.display());
                    Ok(Cache::Corrupt)
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Cache::Missing),
            Err(e) => Err(e),
        }
    };

    // Fast path: no lock needed to read an already-published cache.
    if let Cache::Hit(v) = try_load(path)? {
        return Ok(v);
    }

    let lock_path = sibling(path, ".lock");
    let _lock = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .and_then(|f| f.lock().map(|()| f))
    {
        Ok(f) => Some(f), // released when dropped (or when the process exits)
        Err(e) => {
            tracing::warn!(
                "could not lock {} ({e}); generating without it",
                lock_path.display()
            );
            None
        }
    };

    // Someone may have published while we waited for the lock.
    match try_load(path)? {
        Cache::Hit(v) => return Ok(v),
        Cache::Corrupt => {
            // A corrupt cache would make the exclusive link below fail forever, so
            // clear it. Under the lock only one caller does this per generation.
            tracing::warn!("removing unreadable key cache {}", path.display());
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Cache::Missing => {}
    }

    let (ours, bytes) = generate()?;
    publish_or_adopt(path, ours, &bytes, decode)
}

/// Publish `bytes` at `path` unless someone else already has; return `ours` if we
/// published, else the decoded on-disk value.
///
/// The bytes go to a tmp file unique to this process **and** call (so concurrent
/// writers never share one), which is then hard-linked to `path`. `link(2)` fails
/// with `AlreadyExists` instead of overwriting, so exactly one caller's bytes ever
/// appear at `path`, and it never holds a partially written file. The tmp file is
/// always removed.
fn publish_or_adopt<T>(
    path: &Path,
    ours: T,
    bytes: &[u8],
    decode: impl Fn(&[u8]) -> std::io::Result<T>,
) -> std::io::Result<T> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = sibling(path, &format!(".{}.{seq}.tmp", std::process::id()));

    let result = std::fs::write(&tmp, bytes).and_then(|()| std::fs::hard_link(&tmp, path));
    let _ = std::fs::remove_file(&tmp);
    match result {
        Ok(()) => {
            tracing::info!("published new key cache {}", path.display());
            Ok(ours)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            tracing::info!(
                "lost the publish race for {}; adopting the published keys",
                path.display()
            );
            decode(&std::fs::read(path)?)
        }
        Err(e) => Err(e),
    }
}

/// `path` with `suffix` appended to its file name (`keys.bin` → `keys.bin<suffix>`).
fn sibling(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

/// Build the scan public data for Merkle mode: the callback membership and
/// nonmembership **roots** as public inputs (const flags `false`).
///
/// This is the Merkle counterpart of `personas_core::circuits::get_extra_pubdata_for_scan`,
/// which hardcodes both flags `true` for the centralized (baked-key) circuits.
pub fn merkle_scan_pubdata<const MH: usize, const NH: usize, const N: usize>(
    cstore: &MerkleCallbackStore<F, MH, NH>,
    cur_time: Time<F>,
) -> PubScan<MerkleCallbackStore<F, MH, NH>, N> {
    let memb_root = cstore.memb_root();
    let nmemb_root = cstore.nmemb_root();
    PubScan {
        memb_pub: core::array::from_fn(|_| memb_root),
        is_memb_data_const: false,
        nmemb_pub: core::array::from_fn(|_| nmemb_root),
        is_nmemb_data_const: false,
        cur_time,
        bulletin: cstore.clone(),
        cb_methods: get_callbacks(),
    }
}

/// Generate every Merkle-mode circuit's key pair under SNARK `S`, at the production
/// default heights.
///
/// Structurally identical to [`personas_core::params::generate_server_keys`] but
/// with `None` object membership (root = public input) throughout and the scan
/// callback roots as public inputs. The resulting verifying keys carry extra
/// public inputs for those roots; the replica pins them at verify time.
///
/// `cstore` supplies only the scan circuit's bulletin handle — the keys do **not**
/// bake in its contents (that is the whole point), so a fresh
/// [`MerkleCStore::default`] is a fine argument.
pub fn generate_merkle_circuit_keys<S: SNARK<F>>(
    rng: &mut (impl CryptoRng + RngCore),
    cstore: &MerkleCStore,
) -> MerkleCircuitKeys<S> {
    let (standard_proving_key, standard_verifying_key) = get_standard_interaction()
        .generate_keys::<H, S, Cr, MerkleOStore>(rng, None, F::from(0), false);

    let dummy_pseudo = PseudonymArgs::default();
    let (standard_pseudo_proving_key, standard_pseudo_verifying_key) =
        get_standard_pseudo_interaction().generate_keys::<H, S, Cr, MerkleOStore>(
            rng,
            None,
            dummy_pseudo.clone(),
            false,
        );

    let dummy_pseudo_rate = PseudonymArgsRate::default();
    let (standard_pseudor_proving_key, standard_pseudor_verifying_key) =
        get_standard_pseudo_rate_interaction().generate_keys::<H, S, Cr, MerkleOStore>(
            rng,
            None,
            dummy_pseudo_rate,
            false,
        );

    let dummy_badge_request = BadgesArgs {
        i: F::from(0),
        claimed: F::from(0),
    };
    let (badge_request_proving_key, badge_request_verifying_key) = get_badge_request_interaction()
        .generate_keys::<H, S, Cr, MerkleOStore>(
        rng,
        None,
        dummy_badge_request.clone(),
        false,
    );

    let scan_interaction: ScanInt<MerkleCStore> = get_scan_interaction();
    let dummy_scan = merkle_scan_pubdata::<
        DEFAULT_CB_MEMB_HEIGHT,
        DEFAULT_CB_NMEMB_HEIGHT,
        NUM_SCANS_PER_FOLD,
    >(cstore, Time::default());
    let (scan_proving_key, scan_verifying_key) =
        scan_interaction.generate_keys::<H, S, Cr, MerkleOStore>(rng, None, dummy_scan, true);

    let (pseudonym_pred_proving_key, pseudonym_pred_verifying_key) =
        generate_keys_for_statement_in::<
            F,
            H,
            MsgUser,
            PseudonymArgs<F>,
            PseudonymArgsVar<F>,
            (),
            (),
            S,
            MerkleOStore,
        >(rng, pseudonym_pred, None, dummy_pseudo.clone());

    let dummy_author = PseudonymArgsPair {
        a: dummy_pseudo.clone(),
        b: dummy_pseudo,
    };
    let (authorship_pred_proving_key, authorship_pred_verifying_key) =
        generate_keys_for_statement_in::<
            F,
            H,
            MsgUser,
            PseudonymArgsPair<F>,
            PseudonymArgsPairVar<F>,
            (),
            (),
            S,
            MerkleOStore,
        >(rng, authorship_pred, None, dummy_author);

    let (badge_pred_proving_key, badge_pred_verifying_key) =
        generate_keys_for_statement_in::<
            F,
            H,
            MsgUser,
            BadgesArgs<F>,
            BadgesArgsVar<F>,
            (),
            (),
            S,
            MerkleOStore,
        >(rng, badge_pred, None, dummy_badge_request);

    // A join proves its object is fresh: a statement about the object alone (no
    // membership — it is not in any tree yet), its commitment the first public input.
    let (join_pred_proving_key, join_pred_verifying_key) =
        generate_keys_for_statement::<F, H, MsgUser, JoinArgs<F>, JoinArgsVar<F>, (), (), S>(
            rng,
            join_pred,
            JoinArgs::default(),
        );
    // A reset request proves a CURRENT object (membership) is unbanned and just swept.
    let (not_banned_pred_proving_key, not_banned_pred_verifying_key) =
        generate_keys_for_statement_in::<
            F,
            H,
            MsgUser,
            ResetArgs<F>,
            ResetArgsVar<F>,
            (),
            (),
            S,
            MerkleOStore,
        >(rng, not_banned_pred, None, ResetArgs::default());

    MerkleCircuitKeys {
        standard: (standard_proving_key, standard_verifying_key),
        scan: (scan_proving_key, scan_verifying_key),
        pseudonym_pred: (pseudonym_pred_proving_key, pseudonym_pred_verifying_key),
        authorship_pred: (authorship_pred_proving_key, authorship_pred_verifying_key),
        badge_pred: (badge_pred_proving_key, badge_pred_verifying_key),
        standard_pseudo: (standard_pseudo_proving_key, standard_pseudo_verifying_key),
        standard_pseudor: (standard_pseudor_proving_key, standard_pseudor_verifying_key),
        badge_request: (badge_request_proving_key, badge_request_verifying_key),
        join_pred: (join_pred_proving_key, join_pred_verifying_key),
        not_banned_pred: (not_banned_pred_proving_key, not_banned_pred_verifying_key),
    }
}

/// Every Merkle-mode circuit's key pair, under any SNARK `S`. With Groth16 these are the
/// production keys ([`generate_merkle_server_keys`]); with a counting stand-in they are
/// the circuits' sizes (the benchmark harness), from the very same circuit definitions.
pub struct MerkleCircuitKeys<S: SNARK<F>> {
    pub standard: (S::ProvingKey, S::VerifyingKey),
    pub scan: (S::ProvingKey, S::VerifyingKey),
    pub pseudonym_pred: (S::ProvingKey, S::VerifyingKey),
    pub authorship_pred: (S::ProvingKey, S::VerifyingKey),
    pub badge_pred: (S::ProvingKey, S::VerifyingKey),
    pub standard_pseudo: (S::ProvingKey, S::VerifyingKey),
    pub standard_pseudor: (S::ProvingKey, S::VerifyingKey),
    pub badge_request: (S::ProvingKey, S::VerifyingKey),
    pub join_pred: (S::ProvingKey, S::VerifyingKey),
    pub not_banned_pred: (S::ProvingKey, S::VerifyingKey),
}

/// Generate all Groth16 key sets for Merkle mode, at the production default
/// heights ([`generate_merkle_circuit_keys`] with Groth16).
pub fn generate_merkle_server_keys(
    rng: &mut (impl CryptoRng + RngCore),
    cstore: &MerkleCStore,
) -> ServerKeys {
    let k = generate_merkle_circuit_keys::<Snark>(rng, cstore);
    ServerKeys {
        standard_proving_key: k.standard.0,
        standard_verifying_key: k.standard.1,
        scan_proving_key: k.scan.0,
        scan_verifying_key: k.scan.1,
        pseudonym_pred_proving_key: k.pseudonym_pred.0,
        pseudonym_pred_verifying_key: k.pseudonym_pred.1,
        authorship_pred_proving_key: k.authorship_pred.0,
        authorship_pred_verifying_key: k.authorship_pred.1,
        badge_pred_proving_key: k.badge_pred.0,
        badge_pred_verifying_key: k.badge_pred.1,
        standard_pseudo_proving_key: k.standard_pseudo.0,
        standard_pseudo_verifying_key: k.standard_pseudo.1,
        standard_pseudor_proving_key: k.standard_pseudor.0,
        standard_pseudor_verifying_key: k.standard_pseudor.1,
        badge_request_proving_key: k.badge_request.0,
        badge_request_verifying_key: k.badge_request.1,
        join_pred_proving_key: k.join_pred.0,
        join_pred_verifying_key: k.join_pred.1,
        not_banned_pred_proving_key: k.not_banned_pred.0,
        not_banned_pred_verifying_key: k.not_banned_pred.1,
    }
}

/// Generate just the standard-interaction Merkle key pair (object membership as a
/// public input). Split out for callers/tests that don't need the full bundle.
pub fn generate_merkle_standard_key(rng: &mut (impl CryptoRng + RngCore)) -> (PK, VK) {
    get_standard_interaction().generate_keys::<H, Snark, Cr, MerkleOStore>(
        rng,
        None,
        F::from(0),
        false,
    )
}

/// Generate just the scan Merkle key pair (object membership + callback
/// membership/nonmembership roots all public inputs).
pub fn generate_merkle_scan_key(
    rng: &mut (impl CryptoRng + RngCore),
    cstore: &MerkleCStore,
) -> (PK, VK) {
    let scan_interaction: ScanInt<MerkleCStore> = get_scan_interaction();
    let dummy_scan = merkle_scan_pubdata::<
        DEFAULT_CB_MEMB_HEIGHT,
        DEFAULT_CB_NMEMB_HEIGHT,
        NUM_SCANS_PER_FOLD,
    >(cstore, Time::default());
    scan_interaction.generate_keys::<H, Snark, Cr, MerkleOStore>(rng, None, dummy_scan, true)
}

// Concurrency tests for the publish step, with a cheap payload standing in for the
// real key bundle (which takes minutes to generate). See FINDINGS F8.
#[cfg(test)]
mod publish_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    const THREADS: usize = 8;

    fn decode(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        Ok(bytes.to_vec())
    }

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("personas-publish-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn leftover_tmp_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }

    /// Without the lock, every thread "generates" a distinct payload and races to
    /// publish: exactly one wins, and every thread returns the winner's bytes.
    #[test]
    fn concurrent_publishers_converge_on_one_value() {
        let dir = scratch_dir("race");
        let path = dir.join("keys.bin");
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let (path, barrier) = (path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let ours = vec![i as u8; 4096];
                    barrier.wait();
                    publish_or_adopt(&path, ours.clone(), &ours, decode).unwrap()
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let on_disk = std::fs::read(&path).unwrap();
        assert!(results.iter().all(|r| *r == on_disk), "callers diverged");
        assert!(leftover_tmp_files(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The full path: concurrent callers on an empty dir all return identical
    /// bytes, and the lock means only one of them actually generates.
    #[test]
    fn concurrent_load_or_publish_generates_once() {
        let dir = scratch_dir("lock");
        let path = dir.join("keys.bin");
        let generated = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let (path, barrier, generated) = (path.clone(), barrier.clone(), generated.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_publish(&path, decode, || {
                        generated.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        let v = vec![i as u8; 4096];
                        Ok((v.clone(), v))
                    })
                    .unwrap()
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let on_disk = std::fs::read(&path).unwrap();
        assert!(results.iter().all(|r| *r == on_disk), "callers diverged");
        assert_eq!(
            generated.load(Ordering::SeqCst),
            1,
            "lock should serialize keygen"
        );
        assert!(leftover_tmp_files(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unreadable cache is replaced rather than adopted (the exclusive link
    /// would otherwise keep failing against it).
    #[test]
    fn corrupt_cache_is_regenerated() {
        let dir = scratch_dir("corrupt");
        let path = dir.join("keys.bin");
        std::fs::write(&path, b"garbage").unwrap();
        let strict = |b: &[u8]| {
            if b == b"good" {
                Ok(b.to_vec())
            } else {
                Err(std::io::Error::other("bad"))
            }
        };
        let got =
            load_or_publish(&path, strict, || Ok((b"good".to_vec(), b"good".to_vec()))).unwrap();
        assert_eq!(got, b"good");
        assert_eq!(std::fs::read(&path).unwrap(), b"good");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// End-to-end SNARK tests. These generate real Groth16 keys and proofs, which is
// impractically slow in a debug build, so they are `#[ignore]` by default. Run
// them with:
//
//     cargo test -p personas-bulletin --release -- --ignored merkle::params
//
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
        use personas_core::circuits::{
        PrivScan, PrivScanVar, PubScan as PubScanAlias, PubScanVar, get_scan_interaction,
    };
    use personas_core::{Args, ArgsVar};
    use rand::{SeedableRng, rngs::StdRng};
    use zk_callbacks::generic::bulletin::{PublicUserBul, UserBul};
    use zk_callbacks::generic::user::User;
    use ark_r1cs_std::fields::fp::FpVar;
    use zk_callbacks::impls::centralized::crypto::FakeSigPubkey;

    // Small heights keep the circuits tiny; the mechanism under test (root as a
    // public input) is height-independent.
    const OH: usize = 4;
    const CMH: usize = 4;
    const CNH: usize = 4;
    type ObjT = MerkleObjStore<Fr, OH>;
    type CbT = MerkleCallbackStore<Fr, CMH, CNH>;

    /// Register a fresh user into an object store and return it plus its store.
    fn register_user(rng: &mut (impl CryptoRng + RngCore)) -> (User<Fr, MsgUser>, ObjT) {
        let user = User::create(MsgUser::default(), rng);
        let mut obj = ObjT::new();
        obj.push(user.commit::<H>(), Fr::from(0), vec![]);
        (user, obj)
    }

    /// Real `ensure_merkle_keys` from several threads on one empty dir: all must
    /// return byte-identical keys (FINDINGS F8). Full keygen: ~1.5s in release, slow in debug.
    #[test]
    #[ignore = "generates the full Merkle key bundle; run with --release --ignored"]
    fn concurrent_ensure_merkle_keys_agree() {
        let dir = std::env::temp_dir().join(format!("personas-merkle-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let (dir, barrier) = (dir.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let keys = ensure_merkle_keys(&dir).unwrap();
                    let mut buf = Vec::new();
                    keys.serialize_with_mode(&mut buf, Compress::No).unwrap();
                    buf
                })
            })
            .collect();
        let bufs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(bufs.windows(2).all(|w| w[0] == w[1]), "engines diverged");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A standard post proves object membership against the object **root** as a
    /// public input, and verifies — while a tampered root does not.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn end_to_end_standard_proof_merkle_mode() {
        let mut rng = StdRng::seed_from_u64(0);
        let (pk, vk) = get_standard_interaction().generate_keys::<H, Snark, Cr, ObjT>(
            &mut rng,
            None,
            Fr::from(0),
            false,
        );

        let (mut user, obj) = register_user(&mut rng);

        let exec = user
            .exec_method_create_cb::<H, Fr, FpVar<Fr>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
                &mut rng,
                get_standard_interaction(),
                [FakeSigPubkey::pk()],
                Time::from(0),
                &obj,
                false, // is_memb_data_const — MUST match the None-keygen above
                &pk,
                Fr::from(0),
                (),
            )
            .unwrap();

        let root = obj.root();
        // The real root, supplied as the public membership input, verifies.
        assert!(
            <ObjT as UserBul<Fr, MsgUser>>::verify_interaction::<Args, Snark, 1>(
                &obj,
                exec.new_object,
                exec.old_nullifier,
                Fr::from(0),
                exec.cb_com_list,
                exec.proof.clone(),
                Some(root),
                &vk,
            ),
            "standard proof must verify against the true object root"
        );

        // A tampered root (what a replica pinning a different tree would supply)
        // does not — this is the pinning that closes the door on stale trees.
        assert!(
            !<ObjT as UserBul<Fr, MsgUser>>::verify_interaction::<Args, Snark, 1>(
                &obj,
                exec.new_object,
                exec.old_nullifier,
                Fr::from(0),
                exec.cb_com_list,
                exec.proof,
                Some(root + Fr::from(1)),
                &vk,
            ),
            "standard proof must NOT verify against a wrong object root"
        );
    }

    /// A scan of an uncalled callback proves **nonmembership** against the
    /// callback range **root** as a public input, inside a real Groth16 proof —
    /// the O10-critical gadget, end to end.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn end_to_end_scan_nonmembership_proof_merkle_mode() {
        let mut rng = StdRng::seed_from_u64(0);

        // Keys: standard (to mint an outstanding callback) + scan (Merkle mode).
        let (std_pk, _std_vk) = get_standard_interaction().generate_keys::<H, Snark, Cr, ObjT>(
            &mut rng,
            None,
            Fr::from(0),
            false,
        );
        let cstore = CbT::new();
        let scan_int: ScanInt<CbT> = get_scan_interaction();
        let dummy_scan =
            merkle_scan_pubdata::<CMH, CNH, NUM_SCANS_PER_FOLD>(&cstore, Time::from(0));
        let (scan_pk, scan_vk) =
            scan_int.generate_keys::<H, Snark, Cr, ObjT>(&mut rng, None, dummy_scan, true);

        // Register and post once so the user has one outstanding, uncalled callback.
        let (mut user, mut obj) = register_user(&mut rng);
        let post = user
            .exec_method_create_cb::<H, Fr, FpVar<Fr>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
                &mut rng,
                get_standard_interaction(),
                [FakeSigPubkey::pk()],
                Time::from(0),
                &obj,
                false,
                &std_pk,
                Fr::from(0),
                (),
            )
            .unwrap();
        // The user is now at its post-object; register that so it is a member for the scan.
        obj.push(
            post.new_object,
            post.old_nullifier,
            post.cb_com_list.to_vec(),
        );

        // The callback bulletin never called the ticket, so the scan proves
        // nonmembership. `(false, false)` = both roots are public inputs.
        let (ps, prs) = user.get_scan_arguments::<Args, ArgsVar, Cr, CbT, NUM_SCANS_PER_FOLD>(
            &cstore,
            (false, false),
            Time::from(0),
            get_callbacks(),
        );

        let scan_exec = user
            .interact::<
                H,
                PubScanAlias<CbT, NUM_SCANS_PER_FOLD>,
                PubScanVar<CbT, NUM_SCANS_PER_FOLD>,
                PrivScan<CbT, NUM_SCANS_PER_FOLD>,
                PrivScanVar<CbT, NUM_SCANS_PER_FOLD>,
                Args,
                ArgsVar,
                Cr,
                Snark,
                ObjT,
                0,
            >(
                &mut rng,
                get_scan_interaction::<CbT, NUM_SCANS_PER_FOLD>(),
                [],
                Time::from(0),
                <ObjT as PublicUserBul<Fr, MsgUser>>::get_membership_data(&obj, user.commit::<H>())
                    .unwrap(),
                false, // object membership is a public input
                &scan_pk,
                ps.clone(),
                prs,
                true, // is_scan
            )
            .unwrap();

        // Verify: the scan pub args carry both callback roots (via
        // `to_field_elements` under the false const flags); the object root is
        // the separate membership public input.
        assert!(
            <ObjT as UserBul<Fr, MsgUser>>::verify_interaction::<
                PubScanAlias<CbT, NUM_SCANS_PER_FOLD>,
                Snark,
                0,
            >(
                &obj,
                scan_exec.new_object,
                scan_exec.old_nullifier,
                ps,
                scan_exec.cb_com_list,
                scan_exec.proof,
                Some(obj.root()),
                &scan_vk,
            ),
            "scan nonmembership proof must verify against the true roots"
        );
    }
}
