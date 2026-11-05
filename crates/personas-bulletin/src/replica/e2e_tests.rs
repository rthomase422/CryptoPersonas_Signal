//! End-to-end replica tests with **real Groth16 proofs** (workstream d3).
//!
//! These generate real Merkle-mode keys and proofs, which is impractically slow in
//! a debug build, so they are `#[ignore]` by default. Run them with:
//!
//! ```text
//! cargo test -p personas-bulletin --release -- --ignored replica::e2e
//! ```
//!
//! They exercise the M3 flagship properties the fast tests cannot: three replicas
//! fed the same records in different arrival orders converge on identical roots
//! (§1/§4), a double-spend is resolved to the same winner everywhere (§4), and a
//! ban propagates so that every replica pins it and a stale pre-ban scan is
//! rejected (§5.2, the O10 defense).

use ark_r1cs_std::fields::fp::FpVar;
use rand::{SeedableRng, rngs::StdRng};

use ark_ff::UniformRand;

use personas_core::circuits::{
    BAN_FLAG, MsgUser, NUM_SCANS_PER_FOLD, PrivScan, PrivScanVar, PseudonymArgs, PseudonymArgsVar,
    PubScan, PubScanVar, ScanInt, get_callbacks, get_scan_interaction, get_standard_interaction,
    pseudonym_pred,
};
use personas_core::{Args, ArgsVar, Cr, F, H, PK, Snark, VK, persona};

use zk_callbacks::crypto::enc::AECipherSigZK;
use zk_callbacks::generic::bulletin::{CallbackBul, PublicUserBul};
use zk_callbacks::generic::interaction::generate_keys_for_statement_in;
use zk_callbacks::generic::object::Time;
use zk_callbacks::generic::user::{ExecutedMethod, User};
use zk_callbacks::impls::centralized::crypto::{FakeSigPrivkey, FakeSigPubkey};

use super::record::{Ark, Eh, Flavour, PollKind, Record, encode};
use super::tally::BAN_OPTION;
use super::{Config, Replica, ReplicaKeys, Status};
use crate::merkle::params::merkle_scan_pubdata;
use crate::merkle::{MerkleCallbackStore, MerkleObjStore};

// Tiny heights keep the circuits small; the mechanism under test is
// height-independent (d1's e2e tests make the same choice).
const OH: usize = 4;
const MH: usize = 4;
const NH: usize = 4;
type ObjT = MerkleObjStore<F, OH>;
type CbT = MerkleCallbackStore<F, MH, NH>;

fn standard_keys(rng: &mut StdRng) -> (PK, VK) {
    get_standard_interaction().generate_keys::<H, Snark, Cr, ObjT>(rng, None, F::from(0), false)
}

fn scan_keys(rng: &mut StdRng, cstore: &CbT) -> (PK, VK) {
    let si: ScanInt<CbT> = get_scan_interaction();
    let dummy = merkle_scan_pubdata::<MH, NH, NUM_SCANS_PER_FOLD>(cstore, Time::from(0));
    si.generate_keys::<H, Snark, Cr, ObjT>(rng, None, dummy, true)
}

fn pseudonym_pred_keys(rng: &mut StdRng) -> (PK, VK) {
    let dummy = PseudonymArgs {
        context: F::from(0),
        claimed: F::from(0),
    };
    generate_keys_for_statement_in::<
        F,
        H,
        MsgUser,
        PseudonymArgs<F>,
        PseudonymArgsVar<F>,
        (),
        (),
        Snark,
        ObjT,
    >(rng, pseudonym_pred, None, dummy)
}

/// A `ReplicaKeys` where only `standard` is real; the others are placeholders for
/// a test that never exercises them.
fn standard_only_keys(vk: &VK) -> ReplicaKeys {
    ReplicaKeys {
        standard: vk.clone(),
        pseudo: vk.clone(),
        pseudo_rate: vk.clone(),
        scan: vk.clone(),
        pseudonym_pred: vk.clone(),
        badge_request: vk.clone(),
        join: vk.clone(),
    }
}

/// Register a fresh user and return it plus a `Join` record committing it.
fn make_user(rng: &mut StdRng) -> (User<F, MsgUser>, Record) {
    let user = User::create(MsgUser::default(), rng);
    let join = Record::Join {
        object: Ark(user.commit::<H>()),
        old_nul: Ark(F::from(0)),
        account: Ark(user.commit::<H>()),
        proof: Ark(Default::default()),
    };
    (user, join)
}

/// The object commitment a `Join` record carries.
fn join_object(join: &Record) -> F {
    match join {
        Record::Join { object, .. } => object.0,
        _ => unreachable!("not a join"),
    }
}

/// An anonymous post by `user` against `obj`'s current root.
fn anon_post(
    rng: &mut StdRng,
    user: &mut User<F, MsgUser>,
    obj: &ObjT,
    pk: &PK,
    body: &str,
) -> Record {
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> = user
        .exec_method_create_cb::<H, F, FpVar<F>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
            rng,
            get_standard_interaction(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            obj,
            false,
            pk,
            F::from(0),
            (),
        )
        .expect("post proof");
    Record::Post {
        flavour: Flavour::Anon,
        exec: Ark(exec),
        extra: Ark(vec![]),
        body: body.into(),
        obj_root: Ark(obj.root()),
    }
}

#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn e2e_convergence_out_of_order_delivery() {
    let mut rng = StdRng::seed_from_u64(0);
    let (pk, vk) = standard_keys(&mut rng);
    let keys = standard_only_keys(&vk);

    // One member joins and posts once.
    let (mut user, join) = make_user(&mut rng);
    let mut shadow = ObjT::new();
    shadow.push(join_object(&join), F::from(0), vec![]);
    let post = anon_post(&mut rng, &mut user, &shadow, &pk, "hello serverless");

    let (join_b, join_eh) = encode(&join).unwrap();
    let (post_b, post_eh) = encode(&post).unwrap();

    // Deliver [join, post] and [post, join] to two replicas; both must converge and
    // apply both records.
    let mut roots = Vec::new();
    for order in [vec![&join_b, &post_b], vec![&post_b, &join_b]] {
        let mut r = Replica::<OH, MH, NH>::new(keys.clone(), Config::default())
            .trust_unproven_joins_for_tests();
        for bytes in order {
            r.ingest(bytes.clone()).unwrap();
        }
        assert_eq!(r.status(&join_eh), Some(Status::Applied));
        assert_eq!(
            r.status(&post_eh),
            Some(Status::Applied),
            "the post applies even when it arrives before the join that produces its root"
        );
        roots.push(r.obj_root());
    }
    assert_eq!(roots[0], roots[1], "arrival order must not change the root");
}

#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn e2e_double_spend_resolves_to_one_winner_everywhere() {
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, vk) = standard_keys(&mut rng);
    let keys = standard_only_keys(&vk);

    let (user, join) = make_user(&mut rng);
    let mut shadow = ObjT::new();
    shadow.push(join_object(&join), F::from(0), vec![]);

    // Two posts spending the *same* joined object — a double-spend (identical old
    // nullifier, different new object/proof).
    let mut u1 = user.clone();
    let mut u2 = user.clone();
    let post_a = anon_post(&mut rng, &mut u1, &shadow, &pk, "spend A");
    let post_b = anon_post(&mut rng, &mut u2, &shadow, &pk, "spend B");

    let (join_by, _join_eh) = encode(&join).unwrap();
    let (a_by, a_eh) = encode(&post_a).unwrap();
    let (b_by, b_eh) = encode(&post_b).unwrap();
    // The §4 winner is the smaller envelope hash.
    let (winner, loser) = if a_eh < b_eh {
        (a_eh, b_eh)
    } else {
        (b_eh, a_eh)
    };

    let mut roots = Vec::new();
    for order in [
        vec![&join_by, &a_by, &b_by],
        vec![&b_by, &a_by, &join_by],
        vec![&a_by, &join_by, &b_by],
    ] {
        let mut r = Replica::<OH, MH, NH>::new(keys.clone(), Config::default())
            .trust_unproven_joins_for_tests();
        for bytes in order {
            r.ingest(bytes.clone()).unwrap();
        }
        assert_eq!(r.status(&winner), Some(Status::Applied), "smaller eh wins");
        assert_eq!(
            r.status(&loser),
            Some(Status::Rejected("nullifier already spent")),
            "the double-spend loser is dropped, deterministically"
        );
        roots.push(r.obj_root());
    }
    assert!(
        roots.iter().all(|x| *x == roots[0]),
        "every replica picks the same winner and so the same root"
    );
}

/// All five verifying keys, for a test that exercises posts, votes and scans.
fn full_keys(std_vk: &VK, scan_vk: &VK, pred_vk: &VK) -> ReplicaKeys {
    ReplicaKeys {
        standard: std_vk.clone(),
        pseudo: std_vk.clone(),
        pseudo_rate: std_vk.clone(),
        scan: scan_vk.clone(),
        pseudonym_pred: pred_vk.clone(),
        badge_request: std_vk.clone(),
        join: std_vk.clone(),
    }
}

/// A user with a random secret key (as the real client creates them).
fn member(rng: &mut StdRng) -> User<F, MsgUser> {
    User::create(
        MsgUser {
            sk: F::rand(rng),
            ..Default::default()
        },
        rng,
    )
}

/// A `Join` record's encoded bytes and eh, plus the object it commits.
fn join_of(user: &User<F, MsgUser>) -> (F, Vec<u8>, Eh) {
    let rec = Record::Join {
        object: Ark(user.commit::<H>()),
        old_nul: Ark(F::from(0)),
        account: Ark(user.commit::<H>()),
        proof: Ark(Default::default()),
    };
    let (b, eh) = encode(&rec).unwrap();
    (user.commit::<H>(), b, eh)
}

/// A vote to ban, proved under `pseudonym_pred` at the poll's context.
fn ban_vote(
    rng: &mut StdRng,
    voter: &User<F, MsgUser>,
    shadow_joined: &ObjT,
    root_joined: F,
    poll: Eh,
    pred_pk: &PK,
) -> (Vec<u8>, Eh) {
    let context = poll.context();
    let claimed = persona::pseudonym(&voter.data.sk, &context);
    let (root, path) = <ObjT as PublicUserBul<F, MsgUser>>::get_membership_data(
        shadow_joined,
        voter.commit::<H>(),
    )
    .unwrap();
    assert_eq!(root, root_joined);
    let pseudo = PseudonymArgs { context, claimed };
    let proof = voter
        .prove_statement_and_in::<H, PseudonymArgs<F>, PseudonymArgsVar<F>, (), (), Snark, ObjT>(
            rng,
            pseudonym_pred,
            pred_pk,
            (path, root),
            false,
            pseudo,
            (),
        )
        .expect("vote proof");
    let rec = Record::Vote {
        poll,
        option: BAN_OPTION,
        proof: Ark(proof),
        claimed: Ark(claimed),
        obj_root: Ark(root_joined),
    };
    encode(&rec).unwrap()
}

/// A scan by `user` against callback store `cbs` and object root `obj_root`. When
/// the user's ticket is a member of `cbs` (called), this proves the membership
/// (absorb) branch; otherwise the nonmembership branch.
fn scan_of(
    rng: &mut StdRng,
    user: &mut User<F, MsgUser>,
    shadow: &ObjT,
    cbs: &CbT,
    scan_pk: &PK,
    obj_root: F,
) -> Record {
    let (ps, prs) = user.get_scan_arguments::<Args, ArgsVar, Cr, CbT, NUM_SCANS_PER_FOLD>(
        cbs,
        (false, false),
        Time::from(0),
        get_callbacks(),
    );
    let md = <ObjT as PublicUserBul<F, MsgUser>>::get_membership_data(shadow, user.commit::<H>())
        .unwrap();
    let exec = user
        .interact::<H, PubScan<CbT, NUM_SCANS_PER_FOLD>, PubScanVar<CbT, NUM_SCANS_PER_FOLD>, PrivScan<CbT, NUM_SCANS_PER_FOLD>, PrivScanVar<CbT, NUM_SCANS_PER_FOLD>, Args, ArgsVar, Cr, Snark, ObjT, 0>(
            rng,
            get_scan_interaction::<CbT, NUM_SCANS_PER_FOLD>(),
            [],
            Time::from(0),
            md,
            false,
            scan_pk,
            ps,
            prs,
            true,
        )
        .expect("scan proof");
    Record::Scan {
        exec: Ark(exec),
        obj_root: Ark(obj_root),
        cb_memb_root: Ark(cbs.memb_root()),
        cb_nmemb_root: Ark(cbs.nmemb_root()),
    }
}

/// Invoke a callback with `arg` into a callback store, exactly as `settle_barrier`
/// does — used to reconstruct the replica's post-ban callback store so a member can
/// prove an absorbing scan against it.
fn invoke_into(cbs: &mut CbT, ticket: &super::tally::Callback, arg: F) {
    let enc_key = ticket.cb_entry.enc_key.clone();
    let tik = ticket.cb_entry.tik.clone();
    let (enc, sig) =
        <Cr as AECipherSigZK<F, F>>::encrypt_and_sign(arg, enc_key, FakeSigPrivkey::sk());
    <CbT as CallbackBul<F, F, Cr>>::verify_call_and_append(cbs, tik, enc, sig, Time::from(0))
        .expect("invoke");
    cbs.update_epoch();
}

#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn e2e_ban_propagates_and_absorbs_and_stale_scan_rejected() {
    let mut rng = StdRng::seed_from_u64(2);
    let (std_pk, std_vk) = standard_keys(&mut rng);
    let (scan_pk, scan_vk) = scan_keys(&mut rng, &CbT::new());
    let (pred_pk, pred_vk) = pseudonym_pred_keys(&mut rng);
    let keys = full_keys(&std_vk, &scan_vk, &pred_vk);
    let config = Config {
        root_window: 256,
        settlement_barriers: 3,
        poll_close_barriers: 1,
    };

    // Three members: the target T and two voters.
    let mut t = member(&mut rng);
    let v1 = member(&mut rng);
    let v2 = member(&mut rng);

    // Joins, in the canonical (ascending-eh) order the replica will apply them.
    let mut joins = vec![join_of(&t), join_of(&v1), join_of(&v2)];
    joins.sort_by_key(|j| j.2);
    let mut shadow_joined = ObjT::new();
    for (com, _, _) in &joins {
        shadow_joined.push(*com, F::from(0), vec![]);
    }
    let root_joined = shadow_joined.root();

    // T posts the offending message (anonymous), committing a callback ticket.
    let p_exec = t
        .exec_method_create_cb::<H, F, FpVar<F>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
            &mut rng,
            get_standard_interaction(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            &shadow_joined,
            false,
            &std_pk,
            F::from(0),
            (),
        )
        .expect("post proof");
    let p_new_object = p_exec.new_object;
    let p_old_nul = p_exec.old_nullifier;
    let p_cb_com = p_exec.cb_com_list;
    let p_ticket = p_exec.cb_tik_list[0].0.clone();
    let post = Record::Post {
        flavour: Flavour::Anon,
        exec: Ark(p_exec),
        extra: Ark(vec![]),
        body: "the offending post".into(),
        obj_root: Ark(root_joined),
    };
    let (post_b, post_eh) = encode(&post).unwrap();

    // The object tree after P — what T's scan will prove membership against.
    let mut shadow_after_p = shadow_joined.clone();
    shadow_after_p.push(p_new_object, p_old_nul, p_cb_com.to_vec());
    let root_after_p = shadow_after_p.root();

    // A ban poll targeting P, and two ban votes.
    let poll = Record::PollOpen {
        question: "ban the poster?".into(),
        options: vec!["ban".into(), "keep".into()],
        kind: PollKind::Ban,
        target: Some(post_eh),
    };
    let (poll_b, poll_eh) = encode(&poll).unwrap();
    let (v1_b, _) = ban_vote(
        &mut rng,
        &v1,
        &shadow_joined,
        root_joined,
        poll_eh,
        &pred_pk,
    );
    let (v2_b, _) = ban_vote(
        &mut rng,
        &v2,
        &shadow_joined,
        root_joined,
        poll_eh,
        &pred_pk,
    );

    let base: Vec<Vec<u8>> = joins
        .iter()
        .map(|j| j.1.clone())
        .chain([post_b, poll_b, v1_b, v2_b])
        .collect();

    // (a) Convergence, including the ban: three replicas, three arrival orders,
    //     each crosses one barrier, all agree on every root.
    let mut fingerprints = Vec::new();
    let orders: [Vec<usize>; 3] = [
        vec![0, 1, 2, 3, 4, 5, 6],
        vec![6, 5, 4, 3, 2, 1, 0],
        vec![3, 0, 5, 1, 6, 2, 4],
    ];
    for order in orders {
        let mut r =
            Replica::<OH, MH, NH>::new(keys.clone(), config).trust_unproven_joins_for_tests();
        for &i in &order {
            r.ingest(base[i].clone()).unwrap();
        }
        assert_eq!(r.status(&post_eh), Some(Status::Applied), "post applied");
        assert_eq!(
            r.poll(&poll_eh).unwrap().ban_tally(),
            (2, 0),
            "both bans counted"
        );
        // Before the barrier the callback tree is empty (no ban yet).
        assert_eq!(r.cb_memb_root(), CbT::new().memb_root());
        r.barrier();
        // After the barrier the ban has been settled into the callback tree.
        assert_ne!(
            r.cb_memb_root(),
            CbT::new().memb_root(),
            "the ban is now a called ticket"
        );
        fingerprints.push((r.obj_root(), r.cb_memb_root(), r.cb_nmemb_root()));
    }
    assert!(
        fingerprints.iter().all(|f| *f == fingerprints[0]),
        "every replica converges on the same object AND callback roots — the ban is visible identically to all"
    );

    // Prepare a replica that has seen the ban, for the scan assertions.
    let mut r = Replica::<OH, MH, NH>::new(keys.clone(), config).trust_unproven_joins_for_tests();
    for bytes in &base {
        r.ingest(bytes.clone()).unwrap();
    }
    r.barrier();

    // (b) A stale, pre-ban scan (nonmembership against the empty callback set) is
    //     rejected once the replica has crossed the ban barrier — the O10 defense.
    let mut t_stale = t.clone();
    let stale = scan_of(
        &mut rng,
        &mut t_stale,
        &shadow_after_p,
        &CbT::new(),
        &scan_pk,
        root_after_p,
    );
    let (stale_b, _) = encode(&stale).unwrap();
    assert_eq!(
        r.ingest(stale_b).unwrap(),
        Status::Rejected("scan names a superseded barrier"),
        "a scan proving the ticket was never called is stale after the ban"
    );

    // (c) T's post-ban scan, against the replica's current callback store,
    //     ABSORBS the ban (the membership branch — d1's untested path) and is
    //     accepted.
    let mut cbs_post = CbT::new();
    invoke_into(&mut cbs_post, &p_ticket, F::from(BAN_FLAG));
    let mut t_good = t.clone();
    let good = scan_of(
        &mut rng,
        &mut t_good,
        &shadow_after_p,
        &cbs_post,
        &scan_pk,
        root_after_p,
    );
    let (good_b, _) = encode(&good).unwrap();
    assert_eq!(
        r.ingest(good_b).unwrap(),
        Status::Applied,
        "the honest post-ban scan absorbs the ban and verifies"
    );
    // T's object, having absorbed BAN_FLAG, is now banned.
    assert_eq!(t_good.data.banned, F::from(1), "the scan set banned = 1");
}

#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn verifying_with_a_prepared_key_gives_the_same_answers() {
    // The replica verifies against keys prepared once (PreparedVk) instead of through
    // `verify_interaction` / `Snark::verify`, which re-prepare the key every call. That
    // must change nothing but the speed: same answer for a valid proof, and for every
    // way of naming the wrong public inputs.
    use zk_callbacks::generic::bulletin::UserBul;
    let mut rng = StdRng::seed_from_u64(91);
    let (pk, vk) = standard_keys(&mut rng);
    let (mut user, join) = make_user(&mut rng);
    let mut obj = ObjT::new();
    obj.push(join_object(&join), F::from(0), vec![]);
    let Record::Post { exec, obj_root, .. } = anon_post(&mut rng, &mut user, &obj, &pk, "x") else {
        unreachable!()
    };
    let exec = exec.0;
    let prepared = personas_core::PreparedVk::new(&vk);
    let fresh = ObjT::new();
    let cases = [
        ("valid", exec.new_object, exec.old_nullifier, obj_root.0),
        (
            "wrong root",
            exec.new_object,
            exec.old_nullifier,
            obj_root.0 + F::from(1),
        ),
        (
            "wrong nullifier",
            exec.new_object,
            exec.old_nullifier + F::from(1),
            obj_root.0,
        ),
        (
            "wrong object",
            exec.new_object + F::from(1),
            exec.old_nullifier,
            obj_root.0,
        ),
    ];
    for (i, (label, object, nul, root)) in cases.into_iter().enumerate() {
        let library = <ObjT as UserBul<F, MsgUser>>::verify_interaction::<F, Snark, 1>(
            &fresh,
            object,
            nul,
            F::from(0),
            exec.cb_com_list,
            exec.proof.clone(),
            Some(root),
            &vk,
        );
        let mut cache = std::collections::HashMap::new();
        let ours = super::memo_interaction::<OH, _, 1>(
            &mut cache,
            Eh([i as u8; 32]),
            &prepared,
            object,
            nul,
            F::from(0),
            exec.cb_com_list,
            &exec.proof,
            root,
        );
        assert_eq!(
            ours, library,
            "{label}: prepared and library checks must agree"
        );
        assert_eq!(ours, label == "valid", "{label}");
    }
}

/// Rewrite a record's content and re-encode it until `accept` likes its envelope hash.
/// The `view` claim is outside every proof, so it grinds the hash for free.
fn regrind(
    bytes: &[u8],
    mutate: &dyn Fn(&mut Record),
    accept: &dyn Fn(Eh) -> bool,
) -> (Vec<u8>, Eh) {
    for k in 0u64.. {
        let (mut rec, _) = super::record::decode(bytes).unwrap();
        mutate(&mut rec);
        let claim = super::record::ViewClaim {
            barrier: k,
            digest: [0; 32],
        };
        let (b, eh) = super::record::encode_with_view(&rec, Some(claim)).unwrap();
        if accept(eh) {
            return (b, eh);
        }
    }
    unreachable!()
}

/// What the audit's content tests share: two joined members, and an honest post with its
/// bytes, by the first of them.
struct AuditSetup {
    keys: ReplicaKeys,
    joins: Vec<(F, Vec<u8>, Eh)>,
    shadow: ObjT,
    root: F,
    voter: User<F, MsgUser>,
    pred_pk: PK,
    post: Vec<u8>,
    post_eh: Eh,
    rng: StdRng,
}

fn audit_setup() -> AuditSetup {
    let mut rng = StdRng::seed_from_u64(77);
    let (std_pk, std_vk) = standard_keys(&mut rng);
    let (_scan_pk, scan_vk) = scan_keys(&mut rng, &CbT::new());
    let (pred_pk, pred_vk) = pseudonym_pred_keys(&mut rng);
    let keys = full_keys(&std_vk, &scan_vk, &pred_vk);
    let mut author = member(&mut rng);
    let voter = member(&mut rng);
    let mut joins = vec![join_of(&author), join_of(&voter)];
    joins.sort_by_key(|j| j.2);
    let mut shadow = ObjT::new();
    for (com, _, _) in &joins {
        shadow.push(*com, F::from(0), vec![]);
    }
    let root = shadow.root();
    let exec = author
        .exec_method_create_cb::<H, F, FpVar<F>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
            &mut rng,
            get_standard_interaction(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            &shadow,
            false,
            &std_pk,
            F::from(0),
            (),
        )
        .expect("post proof");
    let post = Record::Post {
        flavour: Flavour::Anon,
        exec: Ark(exec),
        extra: Ark(vec![]),
        body: "honest text".into(),
        obj_root: Ark(root),
    };
    let (post, post_eh) = encode(&post).unwrap();
    AuditSetup {
        keys,
        joins,
        shadow,
        root,
        voter,
        pred_pk,
        post,
        post_eh,
        rng,
    }
}

fn audit_replica(s: &AuditSetup) -> Replica<OH, MH, NH> {
    let config = Config {
        root_window: 256,
        settlement_barriers: 3,
        poll_close_barriers: 1,
    };
    let mut r = Replica::<OH, MH, NH>::new(s.keys.clone(), config).trust_unproven_joins_for_tests();
    for j in &s.joins {
        r.ingest_at(j.1.clone(), 0).unwrap();
    }
    r
}

/// Audit C1: a member keeps a post's proof, changes its text and grinds a smaller hash.
/// The forgery has to be refused, and the author's post has to stand.
#[test]
#[ignore = "audit C1: open until payloads are public inputs (real proofs; --release)"]
fn a_post_body_cannot_be_rewritten_under_its_proof() {
    let s = audit_setup();
    let honest = s.post_eh;
    let (forged, forged_eh) = regrind(
        &s.post,
        &|r| {
            if let Record::Post { body, .. } = r {
                *body = "FORGED text".into();
            }
        },
        &|eh| eh < honest,
    );
    let mut r = audit_replica(&s);
    r.ingest_at(s.post.clone(), 0).unwrap();
    r.ingest_at(forged, 0).unwrap();
    assert_eq!(r.status(&honest), Some(Status::Applied));
    assert!(matches!(r.status(&forged_eh), Some(Status::Rejected(_))));
}

/// Audit C1: changing a ballot's option under its proof must not change the tally.
#[test]
#[ignore = "audit C1: open until payloads are public inputs (real proofs; --release)"]
fn a_ballot_cannot_be_flipped_under_its_proof() {
    let mut s = audit_setup();
    let poll = Record::PollOpen {
        question: "ban?".into(),
        options: vec!["ban".into(), "keep".into()],
        kind: PollKind::Ban,
        target: Some(s.post_eh),
    };
    let (poll_bytes, poll_eh) = encode(&poll).unwrap();
    let (vote, vote_eh) = ban_vote(
        &mut s.rng,
        &s.voter,
        &s.shadow,
        s.root,
        poll_eh,
        &s.pred_pk,
    );
    let (flipped, _) = regrind(
        &vote,
        &|r| {
            if let Record::Vote { option, .. } = r {
                *option = super::tally::KEEP_OPTION;
            }
        },
        &|eh| eh > vote_eh,
    );
    let mut r = audit_replica(&s);
    r.ingest_at(s.post.clone(), 0).unwrap();
    r.ingest_at(poll_bytes, 0).unwrap();
    r.ingest_at(vote, 0).unwrap();
    assert_eq!(r.poll(&poll_eh).unwrap().ban_tally(), (1, 0));
    r.ingest_at(flipped, 0).unwrap();
    assert_eq!(r.poll(&poll_eh).unwrap().ban_tally(), (1, 0));
}

/// Beyond the audit: a Groth16 proof can be re-randomized and `view` is outside it, so a
/// copy of a post with the SAME text can still take a smaller hash. Bans and ratings
/// aimed at the original must keep working, so that copy has to be the same record.
#[test]
#[ignore = "open until a record's identity excludes its proof bytes and view (real proofs; --release)"]
fn a_recoded_copy_of_a_post_does_not_displace_it() {
    let s = audit_setup();
    let honest = s.post_eh;
    let (copy, _) = regrind(&s.post, &|_| {}, &|eh| eh < honest);
    let mut r = audit_replica(&s);
    r.ingest_at(s.post.clone(), 0).unwrap();
    r.ingest_at(copy, 0).unwrap();
    assert_eq!(r.status(&honest), Some(Status::Applied));
}
