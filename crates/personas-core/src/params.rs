//! Server parameter generation and a content-addressed disk cache.
//!
//! The Groth16 keys bake the bulletin store's public keys into the circuits
//! as constants (`is_memb_data_const`), so cached artifacts are only valid
//! for the exact store they were generated against. The upstream `GRSchnorr`
//! stores cannot be serialized (their private keys are unreachable), so
//! [`load_or_create_store`] instead rebuilds the store deterministically from
//! a persisted 32-byte seed — keeping its public keys, and with them every
//! cached artifact, stable across restarts. Bulletin *contents* still live
//! only in memory; persisting them is separate work (server state.rs).

use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_grumpkin::{Fq, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use blake2::{Blake2s256, Digest};
use folding_schemes::FoldingScheme;
use folding_schemes::arith::r1cs::R1CS;
use folding_schemes::folding::nova::PreprocessorParam;
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tracing::info;
use zk_callbacks::generic::fold::{FoldingScan, gen_fold_proof_snark_key};
use zk_callbacks::generic::interaction::{
    generate_keys_for_statement, generate_keys_for_statement_in,
};
use zk_callbacks::generic::object::Time;
use zk_callbacks::generic::scan::PubScanArgs;

use crate::circuits::{
    BadgesArgs, BadgesArgsVar, MsgUser, NF, NP, NUM_SCANS_PER_FOLD, PseudonymArgs,
    PseudonymArgsPair, PseudonymArgsPairVar, PseudonymArgsRate, PseudonymArgsVar, PubScan, ScanInt,
    authorship_pred, badge_pred, get_badge_request_interaction, get_callbacks,
    get_extra_pubdata_for_scan, get_scan_interaction, get_standard_interaction,
    JoinArgs, JoinArgsVar, ResetArgs, ResetArgsVar, get_standard_pseudo_interaction,
    get_standard_pseudo_rate_interaction, join_pred,
    not_banned_pred, pseudonym_pred,
};
use crate::{Args, ArgsVar, CStore, Cr, F, H, OStore, PK, Snark, Store, VK};

/// Bump to invalidate every previously cached artifact.
pub const PARAMS_FORMAT_VERSION: u32 = 1;
/// Dependency revisions the circuits are compiled against. Must be kept in
/// sync with the `[workspace.dependencies]` git pins — a rev bump changes the
/// circuits, so it must change the cache key too.
pub const DEP_REVS: &str = "zk-callbacks=d661879;sonobe=4d4fa08";
/// Bulletin implementation the keys are generated for.
pub const BULLETIN_MODE: &str = "central-grschnorr";

const STORE_SEED_FILE: &str = "store_seed.bin";
const GROTH16_KEYS_FILE: &str = "groth16_keys.bin";
const NOVA_PARAMS_FILE: &str = "nova_params.bin";
const FOLD_PROVING_KEY_FILE: &str = "fold_proving_key.bin";
const FOLD_VERIFYING_KEY_FILE: &str = "fold_verifying_key.bin";

#[derive(Debug, thiserror::Error)]
pub enum ParamsError {
    #[error("params I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("params (de)serialization: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),
    #[error("folding setup: {0}")]
    Folding(String),
}

impl From<folding_schemes::Error> for ParamsError {
    fn from(e: folding_schemes::Error) -> Self {
        Self::Folding(e.to_string())
    }
}

/// All Groth16 key pairs the server hands out and verifies against.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ServerKeys {
    pub standard_proving_key: PK,
    pub standard_verifying_key: VK,
    pub scan_proving_key: PK,
    pub scan_verifying_key: VK,
    pub pseudonym_pred_proving_key: PK,
    pub pseudonym_pred_verifying_key: VK,
    pub authorship_pred_proving_key: PK,
    pub authorship_pred_verifying_key: VK,
    pub badge_pred_proving_key: PK,
    pub badge_pred_verifying_key: VK,
    pub standard_pseudo_proving_key: PK,
    pub standard_pseudo_verifying_key: VK,
    pub standard_pseudor_proving_key: PK,
    pub standard_pseudor_verifying_key: VK,
    pub badge_request_proving_key: PK,
    pub badge_request_verifying_key: VK,
    /// A JOIN: the committed object is fresh (`join_pred`, no membership — the object is
    /// not in any tree yet).
    pub join_pred_proving_key: PK,
    pub join_pred_verifying_key: VK,
    /// A reset request: a current object that is not banned and has just been swept
    /// (`not_banned_pred`, with object membership).
    pub not_banned_pred_proving_key: PK,
    pub not_banned_pred_verifying_key: VK,
}

/// Nova folding material plus the Groth16 keys for the fold-proof SNARK.
#[derive(Clone)]
pub struct FoldingParams {
    pub nova_c1_r1cs: R1CS<Fq>,
    pub nova_c2_r1cs: R1CS<Fr>,
    pub folding_key: NP,
    pub pp_hash: Fq,
    pub pos_config: PoseidonConfig<Fq>,
    pub fold_proving_key: PK,
    pub fold_verifying_key: VK,
}

/// Everything [`ensure_params`] produces.
pub struct ServerArtifacts {
    pub keys: ServerKeys,
    pub folding: FoldingParams,
}

/// Deterministically (re)construct the bulletin store from a seed persisted
/// in `data_dir`, generating the seed from the OS RNG on first run.
///
/// The seed is the store's root secret — the Schnorr signing keys derive from
/// it — so it is written with mode 0600.
pub fn load_or_create_store(data_dir: &Path) -> Result<Store, ParamsError> {
    fs::create_dir_all(data_dir)?;
    let seed_path = data_dir.join(STORE_SEED_FILE);
    let seed: [u8; 32] = if seed_path.exists() {
        fs::read(&seed_path)?.as_slice().try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: expected exactly 32 bytes", seed_path.display()),
            )
        })?
    } else {
        info!("generating fresh store seed at {}", seed_path.display());
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        write_secret(&seed_path, &seed)?;
        seed
    };
    Ok(Store::new(&mut ChaCha20Rng::from_seed(seed)))
}

/// Content address for cached artifacts: commits to the circuit family, fold
/// size, dependency revisions, bulletin mode, and the store public keys that
/// are baked into the circuits as constants.
pub fn cache_key(db: &Store) -> Result<String, ParamsError> {
    let mut hasher = Blake2s256::new();
    hasher.update(
        format!(
            "personas-params;v{PARAMS_FORMAT_VERSION};msguser;nfold={NUM_SCANS_PER_FOLD};{DEP_REVS};{BULLETIN_MODE};"
        )
        .as_bytes(),
    );
    let mut pubkeys = Vec::new();
    db.obj_bul.get_pubkey().serialize_compressed(&mut pubkeys)?;
    db.callback_bul
        .get_pubkey()
        .serialize_compressed(&mut pubkeys)?;
    db.callback_bul
        .nmemb_bul
        .get_pubkey()
        .serialize_compressed(&mut pubkeys)?;
    hasher.update(&pubkeys);
    Ok(hex::encode(&hasher.finalize()[..16]))
}

/// Load all server parameters from the cache under `cache_root`, generating
/// and caching anything missing.
pub fn ensure_params(
    rng: &mut (impl CryptoRng + RngCore),
    db: &Store,
    cache_root: &Path,
) -> Result<ServerArtifacts, ParamsError> {
    let dir = cache_root.join(cache_key(db)?);
    fs::create_dir_all(&dir)?;

    let keys = match read_artifact::<ServerKeys>(&dir.join(GROTH16_KEYS_FILE))? {
        Some(keys) => {
            info!("loaded Groth16 keys from cache {}", dir.display());
            keys
        }
        None => {
            info!("no cached Groth16 keys for this store; generating (slow, one-time)...");
            let keys = generate_server_keys(rng, db);
            write_artifact(&dir.join(GROTH16_KEYS_FILE), &keys)?;
            keys
        }
    };

    let material = match (
        read_artifact::<NP>(&dir.join(NOVA_PARAMS_FILE))?,
        read_artifact::<PK>(&dir.join(FOLD_PROVING_KEY_FILE))?,
        read_artifact::<VK>(&dir.join(FOLD_VERIFYING_KEY_FILE))?,
    ) {
        (Some(np), Some(pk), Some(vk)) => {
            info!("loaded Nova folding params from cache {}", dir.display());
            (np, pk, vk)
        }
        _ => {
            info!("no cached Nova folding params for this store; generating (slow, one-time)...");
            let (np, pk, vk) = generate_folding_material(rng, db)?;
            write_artifact(&dir.join(NOVA_PARAMS_FILE), &np)?;
            write_artifact(&dir.join(FOLD_PROVING_KEY_FILE), &pk)?;
            write_artifact(&dir.join(FOLD_VERIFYING_KEY_FILE), &vk)?;
            (np, pk, vk)
        }
    };

    let (nova_params, fold_pk, fold_vk) = material;
    let folding = folding_params(nova_params, fold_pk, fold_vk)?;
    Ok(ServerArtifacts { keys, folding })
}

/// Generate all Groth16 key pairs against `db`'s public keys.
pub fn generate_server_keys(rng: &mut (impl CryptoRng + RngCore), db: &Store) -> ServerKeys {
    let standard_interaction = get_standard_interaction();
    let dummy_pub_std = F::from(0);
    let (standard_proving_key, standard_verifying_key) = standard_interaction
        .generate_keys::<H, Snark, Cr, OStore>(
            rng,
            Some(db.obj_bul.get_pubkey()),
            dummy_pub_std,
            false,
        );

    let standard_pseudo_interaction = get_standard_pseudo_interaction();
    let dummy_pub_std_pseudo = PseudonymArgs::default();
    let (standard_pseudo_proving_key, standard_pseudo_verifying_key) = standard_pseudo_interaction
        .generate_keys::<H, Snark, Cr, OStore>(
        rng,
        Some(db.obj_bul.get_pubkey()),
        dummy_pub_std_pseudo.clone(),
        false,
    );

    let standard_pseudo_rate_interaction = get_standard_pseudo_rate_interaction();
    let dummy_pub_std_pseudo_rate = PseudonymArgsRate::default();
    let (standard_pseudor_proving_key, standard_pseudor_verifying_key) =
        standard_pseudo_rate_interaction.generate_keys::<H, Snark, Cr, OStore>(
            rng,
            Some(db.obj_bul.get_pubkey()),
            dummy_pub_std_pseudo_rate,
            false,
        );

    let badge_request_interaction = get_badge_request_interaction();
    let dummy_pub_badge_request = BadgesArgs {
        i: F::from(0),
        claimed: F::from(0),
    };
    let (badge_request_proving_key, badge_request_verifying_key) = badge_request_interaction
        .generate_keys::<H, Snark, Cr, OStore>(
            rng,
            Some(db.obj_bul.get_pubkey()),
            dummy_pub_badge_request.clone(),
            false,
        );

    let scan_interaction: ScanInt<CStore> = get_scan_interaction();
    let dummy_pub_scan = get_extra_pubdata_for_scan(
        &db.callback_bul,
        db.callback_bul.get_pubkey(),
        db.callback_bul.nmemb_bul.get_pubkey(),
        Time::default(),
    );
    let (scan_proving_key, scan_verifying_key) = scan_interaction
        .generate_keys::<H, Snark, Cr, OStore>(
            rng,
            Some(db.obj_bul.get_pubkey()),
            dummy_pub_scan,
            true,
        );

    let (pseudonym_pred_proving_key, pseudonym_pred_verifying_key) = generate_keys_for_statement_in::<
        F,
        H,
        MsgUser,
        PseudonymArgs<F>,
        PseudonymArgsVar<F>,
        (),
        (),
        Snark,
        OStore,
    >(
        rng,
        pseudonym_pred,
        Some(db.obj_bul.get_pubkey()),
        dummy_pub_std_pseudo.clone(),
    );

    let dummy_pub_author = PseudonymArgsPair {
        a: dummy_pub_std_pseudo.clone(),
        b: dummy_pub_std_pseudo,
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
            Snark,
            OStore,
        >(
            rng,
            authorship_pred,
            Some(db.obj_bul.get_pubkey()),
            dummy_pub_author,
        );

    let dummy_pub_badge = BadgesArgs {
        i: F::from(0),
        claimed: F::from(0),
    };
    let (badge_pred_proving_key, badge_pred_verifying_key) = generate_keys_for_statement_in::<
        F,
        H,
        MsgUser,
        BadgesArgs<F>,
        BadgesArgsVar<F>,
        (),
        (),
        Snark,
        OStore,
    >(
        rng,
        badge_pred,
        Some(db.obj_bul.get_pubkey()),
        dummy_pub_badge,
    );

    // A join proves its object is fresh: a statement about the object alone (no
    // membership — it is not in any tree yet), its commitment the first public input.
    let (join_pred_proving_key, join_pred_verifying_key) =
        generate_keys_for_statement::<F, H, MsgUser, JoinArgs<F>, JoinArgsVar<F>, (), (), Snark>(
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
            Snark,
            OStore,
        >(
            rng,
            not_banned_pred,
            Some(db.obj_bul.get_pubkey()),
            ResetArgs::default(),
        );

    ServerKeys {
        standard_proving_key,
        standard_verifying_key,
        scan_proving_key,
        scan_verifying_key,
        pseudonym_pred_proving_key,
        pseudonym_pred_verifying_key,
        authorship_pred_proving_key,
        authorship_pred_verifying_key,
        badge_pred_proving_key,
        badge_pred_verifying_key,
        standard_pseudo_proving_key,
        standard_pseudo_verifying_key,
        standard_pseudor_proving_key,
        standard_pseudor_verifying_key,
        badge_request_proving_key,
        badge_request_verifying_key,
        join_pred_proving_key,
        join_pred_verifying_key,
        not_banned_pred_proving_key,
        not_banned_pred_verifying_key,
    }
}

/// Run the Nova preprocessing and fold-proof Groth16 keygen against `db`.
pub fn generate_folding_material(
    rng: &mut (impl CryptoRng + RngCore),
    db: &Store,
) -> Result<(NP, PK, VK), ParamsError> {
    let ps: PubScan<CStore> = PubScanArgs {
        memb_pub: [db.callback_bul.get_pubkey(); NUM_SCANS_PER_FOLD],
        is_memb_data_const: true,
        nmemb_pub: [db.callback_bul.nmemb_bul.get_pubkey(); NUM_SCANS_PER_FOLD],
        is_nmemb_data_const: true,
        cur_time: db.callback_bul.get_epoch(),
        bulletin: db.callback_bul.clone(),
        cb_methods: get_callbacks(),
    };

    let f_circ: FoldingScan<F, MsgUser, Args, ArgsVar, Cr, OStore, CStore, H, NUM_SCANS_PER_FOLD> =
        FoldingScan::new((ps, db.obj_bul.get_pubkey()))?;

    let poseidon_config = poseidon_canonical_config::<F>();
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circ);
    let nova_params = NF::preprocess(&mut *rng, &nova_preprocess_params)?;

    let (fold_proving_key, fold_verifying_key) =
        gen_fold_proof_snark_key::<F, H, MsgUser, Snark, OStore>(
            rng,
            Some(db.obj_bul.get_pubkey()),
        );

    Ok((nova_params, fold_proving_key, fold_verifying_key))
}

/// Rebuild the in-memory folding bundle from (possibly cached) material.
///
/// The R1CS instances and pp hash are recovered from the Nova verifier
/// params, which is exactly where `Nova::init` sources them — no need to
/// instantiate a folding scheme here.
pub fn folding_params(
    nova_params: NP,
    fold_pk: PK,
    fold_vk: VK,
) -> Result<FoldingParams, ParamsError> {
    let pp_hash = nova_params.1.pp_hash()?;
    Ok(FoldingParams {
        nova_c1_r1cs: nova_params.1.r1cs.clone(),
        nova_c2_r1cs: nova_params.1.cf_r1cs.clone(),
        pp_hash,
        pos_config: poseidon_canonical_config::<Fq>(),
        folding_key: nova_params,
        fold_proving_key: fold_pk,
        fold_verifying_key: fold_vk,
    })
}

fn read_artifact<T: CanonicalDeserialize>(path: &Path) -> Result<Option<T>, ParamsError> {
    if !path.exists() {
        return Ok(None);
    }
    let file = BufReader::new(fs::File::open(path)?);
    Ok(Some(T::deserialize_with_mode(
        file,
        Compress::No,
        Validate::No,
    )?))
}

fn write_artifact<T: CanonicalSerialize>(path: &Path, value: &T) -> Result<(), ParamsError> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = BufWriter::new(fs::File::create(&tmp)?);
        value.serialize_with_mode(&mut file, Compress::No)?;
        file.into_inner().map_err(|e| e.into_error())?;
    }
    // rename is atomic: a crash mid-write can never leave a truncated artifact
    fs::rename(&tmp, path)?;
    Ok(())
}

fn write_secret(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_genesis_is_deterministic_and_content_addressed() {
        let dir = std::env::temp_dir().join(format!("personas-params-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        // Same persisted seed -> same store pubkeys -> same cache key.
        let a = load_or_create_store(&dir).unwrap();
        let b = load_or_create_store(&dir).unwrap();
        assert_eq!(cache_key(&a).unwrap(), cache_key(&b).unwrap());

        // A different seed must address a different cache entry.
        let c = load_or_create_store(&dir.join("other")).unwrap();
        assert_ne!(cache_key(&a).unwrap(), cache_key(&c).unwrap());

        let _ = fs::remove_dir_all(&dir);
    }
}
