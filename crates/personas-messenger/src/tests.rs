//! Messenger tests (workstream **d4**).
//!
//! Fast tests exercise the parts that need no proof (carriage over a real
//! [`Incoming`], the no-proof `PollOpen` record). The pipeline and convergence
//! tests need real Groth16 keys/proofs, so they are `#[ignore]` and run in release:
//!
//! ```text
//! cargo test -p personas-messenger --release -- --ignored
//! ```

use super::*;
use personas_bulletin::replica::record::{self, PollKind};
use transport_api::{ConversationId, Incoming, MessageId};

/// A no-proof record survives the full record→carriage→Incoming→carriage→record
/// path — the receive wiring, without any keys.
#[test]
fn a_poll_survives_the_carriage_round_trip() {
    let poll = member::open_poll(
        "ban the poster?",
        render::ban_poll_options(),
        PollKind::Ban,
        None,
    );
    let (bytes, eh) = record::encode(&poll).unwrap();

    let carried = carriage::encode(&bytes);
    let incoming = Incoming::Message {
        id: MessageId("1".into()),
        conversation: ConversationId("room".into()),
        sender: "peer".into(),
        body: carried.body,
        reply_to: None,
        attachments: carried.attachment.into_iter().collect(),
        received_at: 0,
    };

    let recovered = carriage::decode_incoming(&incoming).expect("a record rides here");
    let (back, eh2) = record::decode(&recovered).unwrap();
    assert_eq!(eh, eh2, "carriage preserves the envelope hash");
    assert!(matches!(back, record::Record::PollOpen { .. }));
}

/// Placeholder verifying keys — fine for a proof-free test that only rides a `PollOpen`
/// and drives the heartbeat.
fn placeholder_keys() -> personas_bulletin::replica::ReplicaKeys {
    let vk = ark_groth16::VerifyingKey::default();
    personas_bulletin::replica::ReplicaKeys {
        standard: vk.clone(),
        pseudo: vk.clone(),
        pseudo_rate: vk.clone(),
        scan: vk.clone(),
        badge_request: vk.clone(),
        join: vk.clone(),
        not_banned: vk.clone(),
        pseudonym_pred: vk,
    }
}

/// The heartbeat closes a poll on the shared schedule: a `PollOpen` bucketed into
/// barrier 0 by its service timestamp closes once [`tick`](Messenger::tick) advances the
/// replica past `poll_close_barriers` — no proofs, no manual `barrier()`.
#[test]
fn tick_closes_a_poll_on_the_shared_schedule() {
    use personas_bulletin::replica::Config;
    use transport_api::{ConversationId, Incoming, MessageId};

    let transport: std::sync::Arc<dyn transport_api::Transport> =
        std::sync::Arc::new(transport_mock::MockTransport::new());
    let config = Config::fast();
    let mut m = Messenger::<4, 4, 4>::new(
        transport,
        ConversationId("room".into()),
        placeholder_keys(),
        config,
        None,
    )
    .with_heartbeat(Heartbeat::new(0, 1000));

    let poll = member::open_poll(
        "ban?",
        render::ban_poll_options(),
        record::PollKind::Ban,
        None,
    );
    let (bytes, eh) = record::encode(&poll).unwrap();
    let incoming = Incoming::Message {
        id: MessageId("p".into()),
        conversation: m.conversation().clone(),
        sender: "peer".into(),
        body: carriage::encode(&bytes).body,
        reply_to: None,
        attachments: vec![],
        received_at: 250, // barrier 0 (< 1000 ms)
    };
    m.ingest_incoming(&incoming).unwrap().unwrap();
    assert_eq!(m.replica().poll(&eh).unwrap().opened_barrier, 0);
    assert!(!m.replica().poll(&eh).unwrap().closed);

    // A tick short of the close barrier does nothing…
    m.tick((config.poll_close_barriers - 1) * 1000 + 500);
    assert!(!m.replica().poll(&eh).unwrap().closed);

    // …and one that reaches it closes the poll.
    m.tick(config.poll_close_barriers * 1000 + 500);
    assert!(
        m.replica().poll(&eh).unwrap().closed,
        "the heartbeat closed the poll on cadence"
    );
}

// ---------------------------------------------------------------------------------------
// End-to-end, real Groth16 (#[ignore])
// ---------------------------------------------------------------------------------------

mod e2e {
    use super::super::*;
    use crate::member::{Member, MemberKeys};

    use std::sync::Arc;

    use rand::{SeedableRng, rngs::StdRng};

    use personas_bulletin::merkle::params::merkle_scan_pubdata;
    use personas_bulletin::merkle::{MerkleCallbackStore, MerkleObjStore};
    use personas_bulletin::replica::record::PollKind;
    use personas_bulletin::replica::tally::BAN_OPTION;
    use personas_bulletin::replica::{Config, ReplicaKeys, Status};

    use personas_core::circuits::{
        MsgUser, NUM_SCANS_PER_FOLD, PseudonymArgs, PseudonymArgsVar, ScanInt,
        get_scan_interaction, get_standard_interaction, get_standard_pseudo_interaction,
        pseudonym_pred,
    };
    use personas_core::{Cr, F, H, PK, Snark, VK};

    use futures_util::StreamExt;
    use transport_api::{ConversationId, Incoming, MessageId, Transport};
    use transport_mock::MockTransport;
    use zk_callbacks::generic::interaction::generate_keys_for_statement_in;
    use zk_callbacks::generic::object::Time;

    /// A distinct account for each member a test creates (one join per account).
    fn acct() -> F {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        F::from(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    // Tiny heights: the mechanism is height-independent (d3's e2e make the same call).
    const OH: usize = 32;
    const MH: usize = 4;
    const NH: usize = 4;
    type ObjT = MerkleObjStore<F, OH>;
    type CbT = MerkleCallbackStore<F, MH, NH>;
    type Msg = Messenger<OH, MH, NH>;

    /// The four real key pairs this suite needs (standard post, pseudo post, scan,
    /// and the `pseudonym_pred` statement), generated once at tiny heights.
    struct Keys {
        replica: ReplicaKeys,
        member: MemberKeys,
        not_banned_vk: VK,
    }

    fn keygen(rng: &mut StdRng) -> Keys {
        let (std_pk, std_vk): (PK, VK) = get_standard_interaction()
            .generate_keys::<H, Snark, Cr, ObjT>(rng, None, F::from(0), false);
        let dummy_pseudo = PseudonymArgs::default();
        let (pseudo_pk, pseudo_vk): (PK, VK) = get_standard_pseudo_interaction()
            .generate_keys::<H, Snark, Cr, ObjT>(rng, None, dummy_pseudo.clone(), false);
        let si: ScanInt<CbT> = get_scan_interaction();
        let dummy_scan =
            merkle_scan_pubdata::<MH, NH, NUM_SCANS_PER_FOLD>(&CbT::new(), Time::from(0));
        let (scan_pk, scan_vk): (PK, VK) =
            si.generate_keys::<H, Snark, Cr, ObjT>(rng, None, dummy_scan, true);
        let (pred_pk, pred_vk): (PK, VK) = generate_keys_for_statement_in::<
            F,
            H,
            MsgUser,
            PseudonymArgs<F>,
            PseudonymArgsVar<F>,
            (),
            (),
            Snark,
            ObjT,
        >(rng, pseudonym_pred, None, dummy_pseudo);

        let (join_pk, join_vk): (PK, VK) =
            zk_callbacks::generic::interaction::generate_keys_for_statement::<
                F,
                H,
                MsgUser,
                personas_core::circuits::JoinArgs<F>,
                personas_core::circuits::JoinArgsVar<F>,
                (),
                (),
                Snark,
            >(rng, personas_core::circuits::join_pred, Default::default());
        let (not_banned_pk, not_banned_vk): (PK, VK) = generate_keys_for_statement_in::<
            F,
            H,
            MsgUser,
            personas_core::circuits::ResetArgs<F>,
            personas_core::circuits::ResetArgsVar<F>,
            (),
            (),
            Snark,
            ObjT,
        >(
            rng,
            personas_core::circuits::not_banned_pred,
            None,
            Default::default(),
        );

        Keys {
            not_banned_vk: not_banned_vk.clone(),
            replica: ReplicaKeys {
                standard: std_vk,
                pseudo: pseudo_vk,
                pseudo_rate: scan_vk.clone(),   // unused by this suite
                badge_request: scan_vk.clone(), // unused by this suite
                join: join_vk,
                not_banned: not_banned_vk.clone(),
                scan: scan_vk,
                pseudonym_pred: pred_vk,
            },
            member: MemberKeys {
                standard: std_pk,
                pseudo: pseudo_pk,
                pseudo_rate: scan_pk.clone(),     // unused by this suite
                badge_request: scan_pk.clone(),   // unused by this suite
                authorship_pred: pred_pk.clone(), // unused by this suite
                badge_pred: pred_pk.clone(),      // unused by this suite
                join: join_pk,
                not_banned: not_banned_pk,
                scan: scan_pk,
                pseudonym_pred: pred_pk,
            },
        }
    }

    fn config() -> Config {
        Config {
            root_window: 256,
            settlement_barriers: 10,
            poll_close_barriers: 3,
        }
    }

    /// Cross barriers until what was just sent is in a root members can prove from.
    fn settle(ms: &mut [&mut Msg]) {
        for m in ms {
            for _ in 0..personas_bulletin::replica::SETTLE_LAG {
                m.barrier();
            }
        }
    }

    /// Cross a poll's whole window.
    fn close_poll(ms: &mut [&mut Msg]) {
        for m in ms {
            for _ in 0..config().poll_close_barriers {
                m.barrier();
            }
        }
    }

    /// Deliver a produced record to a messenger through the full carriage → Incoming
    /// → decode → ingest path (idempotent for the sender's own record).
    fn deliver(m: &mut Msg, e: &Emitted) -> Option<Result<Status, record::CodecError>> {
        deliver_at(m, e, 0)
    }

    /// Deliver with an explicit service timestamp, so a test can straddle barrier
    /// boundaries (the skewed-delivery convergence case). The default `deliver` uses `0`
    /// (one bucket), matching the barrier()-driven flagship.
    fn deliver_at(
        m: &mut Msg,
        e: &Emitted,
        received_at: u64,
    ) -> Option<Result<Status, record::CodecError>> {
        let carried = carriage::encode(&e.bytes);
        let incoming = Incoming::Message {
            id: MessageId("delivered".into()),
            conversation: m.conversation().clone(),
            sender: "peer".into(),
            body: carried.body,
            reply_to: None,
            attachments: carried.attachment.into_iter().collect(),
            received_at,
        };
        m.ingest_incoming(&incoming)
    }

    fn fingerprint(m: &Msg) -> (F, F, F) {
        (
            m.replica().obj_root(),
            m.replica().cb_memb_root(),
            m.replica().cb_nmemb_root(),
        )
    }

    /// The M3 flagship, driven end to end through the messenger pipeline: three
    /// members join, one posts under a persona, a ban poll passes, and after a
    /// barrier every replica converges on identical roots, renders the offending
    /// post **flagged** (the rendering gate), and the banned member's honest scan
    /// absorbs the ban.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_convergence_ban_and_flag() {
        let mut rng = StdRng::seed_from_u64(7);
        let keys = keygen(&mut rng);
        let conv = ConversationId("serverless-demo".into());
        let mock = Arc::new(MockTransport::new());
        let transport: Arc<dyn Transport> = mock;

        // Three members, three messengers over the same conversation.
        let mut poster = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let mut v1 = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let mut v2 = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );

        // (1) Everyone joins; deliver all three joins to all three replicas.
        let joins = [
            poster.emit_join(&mut rng, acct()).unwrap(),
            v1.emit_join(&mut rng, acct()).unwrap(),
            v2.emit_join(&mut rng, acct()).unwrap(),
        ];
        for e in &joins {
            deliver(&mut poster, e);
            deliver(&mut v1, e);
            deliver(&mut v2, e);
        }
        settle(&mut [&mut poster, &mut v1, &mut v2]);

        // (2) The poster posts under a persona (so the ban has a linkable author to
        //     flag), against the full-set root everyone now holds.
        let context = F::from(0xABCD);
        let post = poster
            .emit_post_pseudo(&mut rng, "the offending post", context)
            .unwrap();
        let post_eh = post.eh;
        for m in [&mut poster, &mut v1, &mut v2] {
            deliver(m, &post);
        }

        // (3) v1 opens a ban poll targeting the post; both voters vote to ban.
        let poll = v1
            .emit_poll(
                "ban them?",
                render::ban_poll_options(),
                PollKind::Ban,
                Some(post_eh),
            )
            .unwrap();
        let poll_eh = poll.eh;
        for m in [&mut poster, &mut v1, &mut v2] {
            deliver(m, &poll);
        }
        let vote1 = v1.emit_vote(&mut rng, poll_eh, BAN_OPTION).unwrap();
        let vote2 = v2.emit_vote(&mut rng, poll_eh, BAN_OPTION).unwrap();
        for e in [&vote1, &vote2] {
            for m in [&mut poster, &mut v1, &mut v2] {
                deliver(m, e);
            }
        }

        // Before the barrier the poll tally is visible but nothing is settled.
        assert_eq!(poster.replica().poll(&poll_eh).unwrap().ban_tally(), (2, 0));

        // (4) Every replica crosses the poll's window: the poll closes yes>no, the ticket
        //     settles with BAN_FLAG, the callback root advances.
        close_poll(&mut [&mut poster, &mut v1, &mut v2]);

        // (5) Convergence: identical object AND callback roots on all three — the ban
        //     is visible identically to everyone.
        let fp = fingerprint(&poster);
        assert_eq!(fingerprint(&v1), fp, "v1 converges with the poster");
        assert_eq!(fingerprint(&v2), fp, "v2 converges with the poster");
        assert_ne!(
            fp.1,
            CbT::new().memb_root(),
            "the ban is a called ticket now"
        );

        // (6) The rendering gate: the offending post is flagged, not deleted, and the
        //     rendered view is identical across replicas.
        let rendered = poster.render();
        assert_eq!(v1.render(), rendered, "renders converge");
        assert_eq!(v2.render(), rendered, "renders converge");
        assert!(
            rendered
                .iter()
                .any(|line| line.starts_with(render::FLAG_PREFIX)),
            "the banned persona's post is flagged: {rendered:?}"
        );

        // (7) The poster's honest post-ban scan absorbs the ban (banned = 1). It is
        //     produced against the replica's current-barrier callback set and
        //     accepted everywhere.
        let scan = poster.emit_scan(&mut rng).unwrap();
        for m in [&mut poster, &mut v1, &mut v2] {
            assert_eq!(deliver(m, &scan).unwrap().unwrap(), Status::Applied);
        }
        assert_eq!(
            poster.member().unwrap().user.data.banned,
            F::from(1),
            "the scan set banned = 1"
        );
    }

    /// An admin's PERMANENT BAN is one record, not a poll: one barrier later the post's
    /// ticket is invoked with BAN_FLAG, the author's posts are flagged, and the author's
    /// next scan bans them. Nothing anyone votes can undo it.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_an_admin_ban_takes_effect_at_the_next_barrier_with_no_poll() {
        let mut rng = StdRng::seed_from_u64(61);
        let keys = keygen(&mut rng);
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let conv = ConversationId("ban".into());
        let new_member = |rng: &mut StdRng| {
            Msg::new(
                transport.clone(),
                conv.clone(),
                keys.replica.clone(),
                config(),
                Some(Member::create(keys.member.clone(), rng)),
            )
        };
        let mut poster = new_member(&mut rng);
        let mut admin = new_member(&mut rng);
        let joins = [
            poster.emit_join(&mut rng, acct()).unwrap(),
            admin.emit_join(&mut rng, acct()).unwrap(),
        ];
        for e in &joins {
            deliver(&mut poster, e);
            deliver(&mut admin, e);
        }
        settle(&mut [&mut poster, &mut admin]);
        let post = poster
            .emit_post_pseudo(&mut rng, "the offending post", F::from(0xBA4))
            .unwrap();
        deliver(&mut admin, &post);

        let ban = admin.emit_ban(post.eh).unwrap();
        assert_eq!(
            deliver(&mut poster, &ban).unwrap().unwrap(),
            Status::Applied
        );
        assert!(
            admin.replica().derived().polls.is_empty(),
            "no poll is opened"
        );
        settle(&mut [&mut poster, &mut admin]);
        assert_eq!(fingerprint(&poster), fingerprint(&admin), "both agree");
        assert!(
            poster
                .render()
                .iter()
                .any(|line| line.starts_with(render::FLAG_PREFIX)),
            "the banned persona's post is flagged"
        );

        let scan = poster.emit_scan(&mut rng).unwrap();
        assert_eq!(
            deliver(&mut admin, &scan).unwrap().unwrap(),
            Status::Applied
        );
        assert_eq!(
            poster.member().unwrap().user.data.banned,
            F::from(1),
            "banned"
        );
        settle(&mut [&mut poster, &mut admin]);
        // Its persona proofs are no longer satisfiable: either proving refuses, or the
        // proof it makes is rejected by everyone else.
        match poster.emit_post_anon(&mut rng, "still here?") {
            Err(_) => {}
            Ok(post) => assert!(
                matches!(
                    deliver(&mut admin, &post).unwrap().unwrap(),
                    Status::Rejected(_)
                ),
                "a banned member's persona post is refused"
            ),
        }

        // Banning the same post again is the identical record: a duplicate, no change.
        let before = fingerprint(&poster);
        let again = admin.emit_ban(post.eh).unwrap();
        assert_eq!(again.eh, ban.eh);
        deliver(&mut poster, &again);
        assert_eq!(fingerprint(&poster), before);
    }

    /// **The d5 convergence proof.** Four replicas receive the same records in different
    /// arrival orders *and* run their heartbeats out of step, yet converge on
    /// byte-identical roots — because each record's settlement barrier is bucketed from
    /// its shared **service timestamp**, not from any replica's local clock (§4/§14).
    ///
    /// The load-bearing replica is the **observer** `obs`: its clock crosses the
    /// poll-close barrier while the poll is still tied 0–0, *then* both ban votes arrive
    /// late. Under a device-clock cadence those votes would be stamped into the later
    /// barrier — after the poll had already closed with no ban — so the observer would
    /// never ban, forking from everyone. Bucketing by the service timestamp keeps the
    /// votes in the barrier they were cast in, and the from-scratch rebuild counts them
    /// *before* the close: the outcome flips from no-ban to ban, and the observer
    /// converges. (Voter `d` additionally receives its votes before the poll they belong
    /// to, exercising the buffer-then-apply path.)
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_skewed_delivery_still_converges_exactly() {
        let mut rng = StdRng::seed_from_u64(43);
        let keys = keygen(&mut rng);
        let conv = ConversationId("skew".into());
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());

        // The shared schedule every replica buckets against: 1-second barriers anchored
        // at 0, so a record's barrier is exactly `received_at / 1000`.
        let hb = Heartbeat::new(0, 1000);
        let member = |rng: &mut StdRng| {
            Msg::new(
                transport.clone(),
                conv.clone(),
                keys.replica.clone(),
                config(),
                Some(Member::create(keys.member.clone(), rng)),
            )
            .with_heartbeat(hb)
        };
        let mut poster = member(&mut rng);
        let mut c = member(&mut rng); // voter + poll opener
        let mut d = member(&mut rng); // voter
        // The skew replica: an observer (no member key), so it holds no vote of its own —
        // the late votes genuinely decide the ban.
        let mut obs = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            None,
        )
        .with_heartbeat(hb);

        // (1) Joins, all in barrier 0. Every replica needs all three to hold the full-set
        //     root the coming proofs are built on; the delivery order is shuffled per
        //     replica, which the set-committing object tree converges through regardless.
        let jp = poster.emit_join(&mut rng, acct()).unwrap();
        let jc = c.emit_join(&mut rng, acct()).unwrap();
        let jd = d.emit_join(&mut rng, acct()).unwrap();
        let joins = [(&jp, 100u64), (&jc, 150u64), (&jd, 200u64)];
        for &(e, t) in &[joins[0], joins[1], joins[2]] {
            deliver_at(&mut poster, e, t);
        }
        for &(e, t) in &[joins[2], joins[0], joins[1]] {
            deliver_at(&mut c, e, t);
        }
        for &(e, t) in &[joins[1], joins[2], joins[0]] {
            deliver_at(&mut d, e, t);
        }
        for &(e, t) in &[joins[2], joins[1], joins[0]] {
            deliver_at(&mut obs, e, t);
        }
        for m in [&mut poster, &mut c, &mut d, &mut obs] {
            m.tick(2_100);
        }

        // (2) The four "skew set" records, each emitted against the full-join root and
        //     each stamped with a service timestamp in barrier 2. They are emitted now but
        //     delivered in scrambled order below.
        let post = poster
            .emit_post_pseudo(&mut rng, "hot take", F::from(0xBEEFu64))
            .unwrap();
        let poll = c
            .emit_poll(
                "ban them?",
                render::ban_poll_options(),
                PollKind::Ban,
                Some(post.eh),
            )
            .unwrap();
        let vote_c = c.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap();
        let vote_d = d.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap();
        let (post_t, poll_t, vote_c_t, vote_d_t) = (2_300u64, 2_400u64, 2_500u64, 2_600u64);

        // Poster: in order.
        deliver_at(&mut poster, &post, post_t);
        deliver_at(&mut poster, &poll, poll_t);
        deliver_at(&mut poster, &vote_c, vote_c_t);
        deliver_at(&mut poster, &vote_d, vote_d_t);

        // Voter d: both votes arrive before the poll they belong to (buffered), then the
        // poll, then the post — a wholly different order.
        deliver_at(&mut d, &vote_c, vote_c_t);
        deliver_at(&mut d, &vote_d, vote_d_t);
        deliver_at(&mut d, &poll, poll_t);
        deliver_at(&mut d, &post, post_t);

        // Voter c: another order.
        deliver_at(&mut c, &post, post_t);
        deliver_at(&mut c, &vote_c, vote_c_t);
        deliver_at(&mut c, &poll, poll_t);
        deliver_at(&mut c, &vote_d, vote_d_t);

        // Observer: crosses barrier 5 (the poll-close barrier) with the poll open and no
        // votes seen — the poll closes tied, no ban — then the votes arrive *late* and
        // must still count.
        deliver_at(&mut obs, &poll, poll_t);
        deliver_at(&mut obs, &post, post_t);
        obs.tick(5_500);
        assert_eq!(
            obs.replica().poll(&poll.eh).unwrap().ban_tally(),
            (0, 0),
            "the observer closed the poll early with no votes seen yet"
        );
        assert_eq!(
            obs.replica().cb_memb_root(),
            CbT::new().memb_root(),
            "and with the poll tied, nothing was banned: the callback set is still empty"
        );
        deliver_at(&mut obs, &vote_d, vote_d_t);
        deliver_at(&mut obs, &vote_c, vote_c_t);

        // (3) Every heartbeat reaches barrier 6 (past the poll close). The observer is at
        //     barrier 5 already; the others jump straight from 2.
        for m in [&mut poster, &mut c, &mut d, &mut obs] {
            m.tick(6_500);
        }

        // (4) Exact convergence: identical object AND callback roots on all four.
        let fp = fingerprint(&poster);
        assert_eq!(
            fingerprint(&obs),
            fp,
            "the observer converges though it crossed the poll-close barrier before its votes arrived"
        );
        assert_eq!(fingerprint(&c), fp, "voter c converges");
        assert_eq!(
            fingerprint(&d),
            fp,
            "voter d converges though its votes were buffered ahead of their poll"
        );
        assert_ne!(
            fp.1,
            CbT::new().memb_root(),
            "the ban settled as a called ticket"
        );
        assert_eq!(
            obs.replica().poll(&poll.eh).unwrap().ban_tally(),
            (2, 0),
            "the late votes retroactively counted (bucketed into barrier 0), flipping the outcome to a ban"
        );

        // (5) Renders converge, with the pseudonymous post flagged everywhere (§9).
        let rendered = poster.render();
        assert_eq!(obs.render(), rendered, "the observer's view matches");
        assert_eq!(c.render(), rendered, "voter c's view matches");
        assert_eq!(d.render(), rendered, "voter d's view matches");
        assert!(
            rendered
                .iter()
                .any(|line| line.starts_with(render::FLAG_PREFIX)),
            "the banned persona's post is flagged: {rendered:?}"
        );
    }

    /// A stale, pre-ban scan is rejected once a replica has crossed the ban barrier —
    /// O10, carried through the messenger layer (§5.2). Isolated from the flagship so
    /// the assertion is unambiguous.
    /// The messenger withholds one member's post from another (§5.5). The next record
    /// sent by someone who saw it carries a view claim the deprived member cannot
    /// match, and the reverse holds too. A member who holds the post relays it, and
    /// the deprived member's view, state and future claims then match the group's.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_a_withheld_post_is_detected_and_relayed() {
        let mut rng = StdRng::seed_from_u64(55);
        let keys = keygen(&mut rng);
        let conv = ConversationId("views".into());
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let hb = Heartbeat::new(0, 1000);
        let member = |rng: &mut StdRng| {
            Msg::new(
                transport.clone(),
                conv.clone(),
                keys.replica.clone(),
                config(),
                Some(Member::create(keys.member.clone(), rng)),
            )
            .with_heartbeat(hb)
            .with_view_checks(true)
        };
        let mut a = member(&mut rng);
        let mut b = member(&mut rng);
        let mut c = member(&mut rng);

        let joins = [
            a.emit_join(&mut rng, acct()).unwrap(),
            b.emit_join(&mut rng, acct()).unwrap(),
            c.emit_join(&mut rng, acct()).unwrap(),
        ];
        for m in [&mut a, &mut b, &mut c] {
            for j in &joins {
                deliver_at(m, j, 100);
            }
            m.tick(2_050);
        }

        // `a` posts in barrier 2, and the messenger delivers it to `a` and `b` only.
        let hidden = a
            .emit_post_anon(&mut rng, "only some of you see this")
            .unwrap();
        deliver_at(&mut a, &hidden, 2100);
        deliver_at(&mut b, &hidden, 2100);
        for m in [&mut a, &mut b, &mut c] {
            m.tick(4500);
        }
        assert_ne!(a.replica().view_digest(2), c.replica().view_digest(2));

        // `b` and `c` each post in barrier 4, and these reach everyone. Each carries a
        // claim about barrier 2.
        let from_b = b.emit_post_anon(&mut rng, "b").unwrap();
        let from_c = c.emit_post_anon(&mut rng, "c").unwrap();
        for m in [&mut a, &mut b, &mut c] {
            deliver_at(m, &from_b, 4100);
            deliver_at(m, &from_c, 4200);
            m.tick(6500);
        }
        let report = a.view_report();
        assert_eq!(report.mismatches.len(), 1, "{report:?}");
        assert_eq!(report.mismatches[0].record, from_c.eh);
        assert!(c.view_report().diverged(), "c sees b's claim disagree too");
        assert!(c.replica().status(&hidden.eh).is_none());

        // `a` relays what it holds around the mismatch; the relay reaches `c`.
        let relays = a.take_relays();
        assert!(
            relays
                .iter()
                .any(|(_, bytes)| record::decode(bytes).unwrap().1 == hidden.eh)
        );
        assert!(a.take_relays().is_empty(), "each record is relayed once");
        for (first_barrier, bytes) in &relays {
            let incoming = Incoming::Message {
                id: MessageId("relay".into()),
                conversation: c.conversation().clone(),
                sender: "peer".into(),
                body: carriage::encode_relay(*first_barrier, bytes),
                reply_to: None,
                attachments: vec![],
                received_at: 6600,
            };
            c.ingest_incoming(&incoming).unwrap().unwrap();
        }
        assert_eq!(c.replica().first_barrier(&hidden.eh), Some(2));
        assert_eq!(c.replica().status(&hidden.eh), Some(Status::Applied));
        for barrier in 0..7 {
            assert_eq!(
                a.replica().view_digest(barrier),
                c.replica().view_digest(barrier)
            );
        }
        assert_eq!(fingerprint(&a), fingerprint(&c));

        // With view checks off (the default), a record carries no claim, relays are
        // ignored and nothing is reported.
        let mut off = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        )
        .with_heartbeat(hb);
        off.tick(6500);
        let join = off.emit_join(&mut rng, acct()).unwrap();
        assert_eq!(record::decode_with_view(&join.bytes).unwrap().2, None);
        assert!(
            off.ingest_relayed(relays[0].1.clone(), relays[0].0, 6600)
                .is_ok()
        );
        assert!(
            off.replica()
                .status(&record::Eh::of_bytes(&relays[0].1))
                .is_none()
        );
        assert!(off.take_relays().is_empty() && !off.view_report().diverged());

        // From here on, `c`'s claims agree with everyone's.
        for m in [&mut a, &mut b, &mut c] {
            m.tick(20_500);
        }
        let later = c.emit_post_anon(&mut rng, "caught up").unwrap();
        for m in [&mut a, &mut b, &mut c] {
            deliver_at(m, &later, 20_600);
            m.tick(23_500);
            let report = m.view_report();
            assert!(!report.diverged(), "{report:?}");
            assert_eq!(report.agreeing, 1);
        }
    }

    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_stale_scan_is_rejected_after_the_ban() {
        let mut rng = StdRng::seed_from_u64(11);
        let keys = keygen(&mut rng);
        let conv = ConversationId("stale-scan".into());
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());

        let mut poster = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let mut v1 = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let mut v2 = Msg::new(
            transport,
            conv,
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );

        let joins = [
            poster.emit_join(&mut rng, acct()).unwrap(),
            v1.emit_join(&mut rng, acct()).unwrap(),
            v2.emit_join(&mut rng, acct()).unwrap(),
        ];
        for e in &joins {
            deliver(&mut poster, e);
            deliver(&mut v1, e);
            deliver(&mut v2, e);
        }
        settle(&mut [&mut poster, &mut v1, &mut v2]);

        // The poster posts (anon is fine here) and captures a stale scan against the
        // EMPTY callback set *before* any ban — the archived nonmembership range.
        let post = poster
            .emit_post_pseudo(&mut rng, "post", F::from(1))
            .unwrap();
        for m in [&mut poster, &mut v1, &mut v2] {
            deliver(m, &post);
        }
        settle(&mut [&mut poster, &mut v1, &mut v2]);
        // Fork the poster's member to build the stale scan without consuming the
        // object it will later scan for real.
        let mut stale_member = poster.member().unwrap().clone();
        let stale = stale_member
            .scan(
                &mut rng,
                poster.replica().proving_store().unwrap(),
                &CbT::new(),
            )
            .expect("stale scan proof");
        let (stale_bytes, _) = record::encode(&stale).unwrap();

        // Ban the post and cross the barrier on v1.
        let poll = v1
            .emit_poll(
                "ban?",
                render::ban_poll_options(),
                PollKind::Ban,
                Some(post.eh),
            )
            .unwrap();
        for m in [&mut poster, &mut v1, &mut v2] {
            deliver(m, &poll);
        }
        for e in [
            v1.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap(),
            v2.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap(),
        ] {
            for m in [&mut poster, &mut v1, &mut v2] {
                deliver(m, &e);
            }
        }
        close_poll(&mut [&mut v1]);

        // The stale scan, delivered to the barrier-crossed replica, is rejected: it
        // names a superseded (pre-ban) callback barrier.
        let stale_incoming = Incoming::Message {
            id: MessageId("stale".into()),
            conversation: v1.conversation().clone(),
            sender: "peer".into(),
            body: carriage::encode(&stale_bytes).body,
            reply_to: None,
            attachments: vec![],
            received_at: 0,
        };
        assert_eq!(
            v1.ingest_incoming(&stale_incoming).unwrap().unwrap(),
            Status::Rejected("scan names a superseded barrier"),
        );
    }

    /// A member that restarts comes back as itself: its saved object and its journalled
    /// records restore a replica identical to its peers', it is still on the bulletin,
    /// a pseudonym keeps its petname, and its next post is accepted by everyone.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_restart_restores_member_and_replica() {
        let mut rng = StdRng::seed_from_u64(31);
        let keys = keygen(&mut rng);
        let conv = ConversationId("restart".into());
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());

        let mut poster = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let mut peer = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        for e in [
            poster.emit_join(&mut rng, acct()).unwrap(),
            peer.emit_join(&mut rng, acct()).unwrap(),
        ] {
            deliver(&mut poster, &e);
            deliver(&mut peer, &e);
        }
        settle(&mut [&mut poster, &mut peer]);
        let first = poster
            .emit_post_pseudo(&mut rng, "before the restart", F::from(9))
            .unwrap();
        deliver(&mut peer, &first);

        // What a client persists: the member's object (saved BEFORE the post went out)
        // and every record with the barrier it sits at.
        let state = poster.export_member_state().unwrap().unwrap();
        let records = poster.replica().seen_with_barriers();
        let barrier = poster.replica().current_barrier();
        drop(poster);

        // How the app restores: an empty replica, then the whole journal imported at once.
        let journal = records
            .iter()
            .map(|(at, bytes)| {
                let eh = personas_bulletin::replica::record::decode(bytes).unwrap().1;
                (*at, eh, bytes.clone())
            })
            .collect();
        let mut imported = Msg::restore(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::from_state(&state, keys.member.clone()).unwrap()),
            Vec::new(),
            barrier,
        );
        imported.import_records(journal, barrier);
        assert_eq!(fingerprint(&imported), fingerprint(&peer));
        assert!(
            imported.member_on_bulletin(),
            "a journal import keeps the object on the tree"
        );

        let mut restored = Msg::restore(
            transport,
            conv,
            keys.replica.clone(),
            config(),
            Some(Member::from_state(&state, keys.member.clone()).unwrap()),
            records,
            barrier,
        );
        assert_eq!(fingerprint(&restored), fingerprint(&peer));
        assert!(
            restored.member_on_bulletin(),
            "the restored object is on the tree"
        );
        settle(&mut [&mut restored, &mut peer]);

        let second = restored
            .emit_post_pseudo(&mut rng, "after the restart", F::from(9))
            .unwrap();
        assert_eq!(
            second.persona, first.persona,
            "the same secret key and context give the same pseudonym"
        );
        assert_eq!(
            deliver(&mut peer, &second).unwrap().unwrap(),
            Status::Applied,
            "a peer accepts the restored member's post"
        );
        assert_eq!(fingerprint(&restored), fingerprint(&peer));
    }

    /// The two-step scan. A prepared scan blocks every other emit, is not reflected in
    /// the saved state, goes stale when a settlement re-pins the callback roots, and can
    /// then be discarded — restoring the exact pre-scan object — and redone. The redone
    /// scan is accepted everywhere and absorbs the ban. A committed scan cannot be
    /// discarded.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_prepared_scan_is_checked_before_release() {
        let mut rng = StdRng::seed_from_u64(37);
        let keys = keygen(&mut rng);
        let conv = ConversationId("prepared-scan".into());
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let new_member = |rng: &mut StdRng| {
            Msg::new(
                transport.clone(),
                conv.clone(),
                keys.replica.clone(),
                config(),
                Some(Member::create(keys.member.clone(), rng)),
            )
        };
        let mut poster = new_member(&mut rng);
        let mut v1 = new_member(&mut rng);
        let mut v2 = new_member(&mut rng);

        let joins = [
            poster.emit_join(&mut rng, acct()).unwrap(),
            v1.emit_join(&mut rng, acct()).unwrap(),
            v2.emit_join(&mut rng, acct()).unwrap(),
        ];
        for e in &joins {
            for m in [&mut poster, &mut v1, &mut v2] {
                deliver(m, e);
            }
        }
        settle(&mut [&mut poster, &mut v1, &mut v2]);
        let post = poster
            .emit_post_pseudo(&mut rng, "post", F::from(1))
            .unwrap();
        for m in [&mut poster, &mut v1, &mut v2] {
            deliver(m, &post);
        }
        settle(&mut [&mut poster, &mut v1, &mut v2]);

        let before = poster.export_member_state().unwrap().unwrap();
        poster.prepare_scan(&mut rng, false).expect("prepare");
        assert!(poster.scan_still_valid());
        assert!(
            matches!(
                poster.emit_post_anon(&mut rng, "x"),
                Err(SendError::ScanPending)
            ),
            "nothing else may be produced while a scan is pending"
        );
        assert_eq!(
            poster.export_member_state().unwrap().unwrap(),
            before,
            "a prepared scan revealed nothing, so the saved state is the pre-scan one"
        );

        // A ban settles on every replica: the callback roots move, the prepared scan is stale.
        let poll = v1
            .emit_poll(
                "ban?",
                render::ban_poll_options(),
                PollKind::Ban,
                Some(post.eh),
            )
            .unwrap();
        for m in [&mut poster, &mut v1, &mut v2] {
            deliver(m, &poll);
        }
        for e in [
            v1.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap(),
            v2.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap(),
        ] {
            for m in [&mut poster, &mut v1, &mut v2] {
                deliver(m, &e);
            }
        }
        close_poll(&mut [&mut poster, &mut v1, &mut v2]);
        assert!(
            !poster.scan_still_valid(),
            "the settlement made the scan stale"
        );

        poster.discard_scan().unwrap();
        assert_eq!(
            poster.export_member_state().unwrap().unwrap(),
            before,
            "a discard restores the exact pre-scan object"
        );

        poster.prepare_scan(&mut rng, false).expect("re-prepare");
        assert!(poster.scan_still_valid());
        let scan = poster.commit_scan().unwrap();
        assert!(matches!(
            poster.discard_scan(),
            Err(SendError::NoPreparedScan)
        ));
        for m in [&mut v1, &mut v2] {
            assert_eq!(deliver(m, &scan).unwrap().unwrap(), Status::Applied);
        }
        assert_eq!(fingerprint(&poster), fingerprint(&v1));
        assert_ne!(
            poster.member().unwrap().user.data.banned,
            F::from(0u64),
            "the redone scan absorbed the ban"
        );
    }

    /// Scanning only when it absorbs something, and measuring a sweep by its own
    /// progress. Three posts file three callbacks; nothing is invoked yet, so no scan is
    /// needed. Once settlement invokes them, a scan is needed, the sweep takes one scan
    /// per callback (the outstanding count does NOT move until it ends), and afterwards
    /// nothing is left to absorb.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_scan_needed_and_sweep_progress() {
        let mut rng = StdRng::seed_from_u64(41);
        let keys = keygen(&mut rng);
        let conv = ConversationId("sweep".into());
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let mut m = Msg::new(
            transport,
            conv,
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let join = m.emit_join(&mut rng, acct()).unwrap();
        deliver(&mut m, &join);
        settle(&mut [&mut m]);
        for i in 0..3u64 {
            let e = m
                .emit_post_pseudo(&mut rng, "post", F::from(100 + i))
                .unwrap();
            deliver(&mut m, &e);
            settle(&mut [&mut m]);
        }
        assert_eq!(m.member().unwrap().user.num_outstanding_callbacks(), 3);
        assert!(
            !m.scan_needed(),
            "nothing invoked yet: a scan would absorb nothing"
        );

        // Cross the settlement window: every post's ticket is invoked.
        for _ in 0..=config().settlement_barriers {
            m.barrier();
        }
        assert!(
            m.scan_needed(),
            "invoked callbacks are waiting to be absorbed"
        );

        let mut remaining = Vec::new();
        for _ in 0..3 {
            m.prepare_scan(&mut rng, false).unwrap();
            let scan = m.commit_scan().unwrap();
            deliver(&mut m, &scan);
            remaining.push(m.sweep_remaining());
            settle(&mut [&mut m]);
        }
        assert_eq!(remaining, vec![2, 1, 0], "one scan per callback");
        assert!(
            !m.member().unwrap().user.is_scanning(),
            "the sweep finished"
        );
        assert_eq!(
            m.member().unwrap().user.num_outstanding_callbacks(),
            0,
            "absorbed callbacks leave the list only when the sweep ends"
        );
        assert!(!m.scan_needed());
    }

    /// A badge proof is only as good as the root it is made against. A forger gives its
    /// own object the public FACULTY value (no approval, no callback), builds a one-leaf
    /// tree around it and proves possession: the proof verifies cryptographically, but its
    /// root is not one the group's replica ever produced, which is what the verifier must
    /// check (`Replica::has_produced_root`).
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_forged_badge_proof_names_a_root_the_group_never_had() {
        use personas_core::circuits::{BadgesArgs, BadgesArgsVar, FACULTY_F, badge_pred};
        let mut rng = StdRng::seed_from_u64(43);
        let keys = keygen(&mut rng);
        let (badge_pk, badge_vk): (PK, VK) = generate_keys_for_statement_in::<
            F,
            H,
            MsgUser,
            BadgesArgs<F>,
            BadgesArgsVar<F>,
            (),
            (),
            Snark,
            ObjT,
        >(
            &mut rng,
            badge_pred,
            None,
            BadgesArgs {
                i: F::from(1u64),
                claimed: F::from(0u64),
            },
        );
        let mut member_keys = keys.member.clone();
        member_keys.badge_pred = badge_pk;

        // A real group the forger is not part of.
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let mut group = Msg::new(
            transport,
            ConversationId("forgery".into()),
            keys.replica.clone(),
            config(),
            Some(Member::create(member_keys.clone(), &mut rng)),
        );
        let join = group.emit_join(&mut rng, acct()).unwrap();
        deliver(&mut group, &join);
        group.barrier();

        let mut forger = Member::create(member_keys, &mut rng);
        forger.user.data.badge1 = *FACULTY_F;
        let mut own_tree = ObjT::new();
        own_tree.push(forger.commitment(), F::from(0u64), Vec::new());
        let (root, proof) = forger
            .badge(&mut rng, &own_tree, F::from(1u64), *FACULTY_F)
            .expect("a proof against the forger's own tree");
        let bytes =
            personas_core::encode_badge_proof(&proof, &[F::from(1u64), *FACULTY_F, root]).unwrap();

        assert!(
            personas_core::verify_badge_proof(&badge_vk, &bytes).is_some(),
            "the forged proof is cryptographically valid — which is the whole problem"
        );
        assert!(
            !group.replica().has_produced_root(root),
            "but its root is not one the group produced, so it must be refused"
        );
        assert!(
            group
                .replica()
                .has_produced_root(group.replica().obj_root())
        );
    }

    /// Proven joins, one per account, and the admin-approved re-join a reset needs.
    #[test]
    fn e2e_a_late_joiner_catches_up_then_sends_and_receives() {
        // Members who joined after the group started posting used to be stranded: their
        // posts named a tree nobody else had, and everyone else's named trees they never
        // built. With an admin's history (private text removed) they can take part.
        let mut rng = StdRng::seed_from_u64(53);
        let keys = keygen(&mut rng);
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let conv = ConversationId("late".into());
        let new_member = |rng: &mut StdRng| {
            Msg::new(
                transport.clone(),
                conv.clone(),
                keys.replica.clone(),
                config(),
                Some(Member::create(keys.member.clone(), rng)),
            )
        };
        let status = |m: &mut Msg, e: &Emitted| deliver(m, e).unwrap().unwrap();

        let mut admin = new_member(&mut rng);
        let mut alice = new_member(&mut rng);
        let j = admin.emit_join(&mut rng, F::from(7001u64)).unwrap();
        status(&mut alice, &j);
        let j = alice.emit_join(&mut rng, F::from(7002u64)).unwrap();
        status(&mut admin, &j);
        settle(&mut [&mut admin, &mut alice]);
        let p = alice.emit_post_anon(&mut rng, "an old secret").unwrap();
        assert_eq!(status(&mut admin, &p), Status::Applied);
        let old_post = p.eh;
        settle(&mut [&mut admin, &mut alice]);

        // A newcomer WITHOUT the history: its post is held back by everyone.
        let mut stranded = new_member(&mut rng);
        let j = stranded.emit_join(&mut rng, F::from(7003u64)).unwrap();
        for m in [&mut admin, &mut alice] {
            status(m, &j);
        }
        settle(&mut [&mut stranded]);
        let p = stranded.emit_post_anon(&mut rng, "hello?").unwrap();
        assert_eq!(status(&mut admin, &p), Status::Buffered, "the old failure");
        assert_eq!(status(&mut alice, &p), Status::Buffered);

        // A newcomer WITH it.
        let mut bob = new_member(&mut rng);
        let history = admin.catch_up_records();
        assert!(
            history
                .iter()
                .all(|(_, _, b)| !String::from_utf8_lossy(b).contains("an old secret")),
            "the history carries no message text"
        );
        let at = admin.replica().current_barrier();
        assert!(bob.import_records(history, at) > 0);
        assert_eq!(bob.replica().obj_root(), admin.replica().obj_root());
        assert_eq!(
            bob.replica()
                .log()
                .iter()
                .find(|e| e.eh == old_post)
                .map(|e| e.body.clone()),
            Some(String::new()),
            "old posts are known to the replica, but not their text"
        );

        let j = bob.emit_join(&mut rng, F::from(7004u64)).unwrap();
        for m in [&mut admin, &mut alice] {
            assert_eq!(status(m, &j), Status::Applied);
        }
        settle(&mut [&mut admin, &mut alice, &mut bob]);
        let p = bob.emit_post_anon(&mut rng, "hi all").unwrap();
        for m in [&mut admin, &mut alice] {
            assert_eq!(status(m, &p), Status::Applied, "bob can send");
        }
        let p = alice.emit_post_anon(&mut rng, "welcome").unwrap();
        status(&mut admin, &p);
        assert_eq!(status(&mut bob, &p), Status::Applied, "bob can receive");
        assert_eq!(bob.replica().obj_root(), admin.replica().obj_root());
    }

    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_proven_joins_one_per_account_and_admin_rejoin() {
        use personas_core::circuits::{FACULTY_F, join_pred};
        let mut rng = StdRng::seed_from_u64(47);
        let keys = keygen(&mut rng);
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let conv = ConversationId("joins".into());
        let new_member = |rng: &mut StdRng| {
            Msg::new(
                transport.clone(),
                conv.clone(),
                keys.replica.clone(),
                config(),
                Some(Member::create(keys.member.clone(), rng)),
            )
        };
        let mut admin = new_member(&mut rng);
        let mut alice = new_member(&mut rng);
        let (admin_acct, alice_acct) = (F::from(9001u64), F::from(9002u64));
        let status = |m: &mut Msg, e: &Emitted| deliver(m, e).unwrap().unwrap();
        // Records in one barrier are ordered by eh, not by arrival; the client keeps a
        // re-join a barrier after its approval, and so does this test.
        let tick = |mut ms: [&mut Msg; 2]| settle(&mut ms);

        let j = admin.emit_join(&mut rng, admin_acct).unwrap();
        status(&mut alice, &j);
        let j = alice.emit_join(&mut rng, alice_acct).unwrap();
        assert_eq!(
            status(&mut admin, &j),
            Status::Applied,
            "a fresh, proven join"
        );

        // A doctored object cannot produce an acceptable join...
        let mut forger = Member::create(keys.member.clone(), &mut rng);
        forger.user.data.badge1 = *FACULTY_F;
        assert!(matches!(
            forger.join(&mut rng, F::from(1u64)),
            Err(MemberError::NotFresh)
        ));
        let forced = forger
            .user
            .prove_statement::<
                H,
                personas_core::circuits::JoinArgs<F>,
                personas_core::circuits::JoinArgsVar<F>,
                (),
                (),
                Snark,
            >(
                &mut rng,
                join_pred,
                &keys.member.join,
                personas_core::circuits::JoinArgs {
                    account: F::from(1u64),
                    pk: persona::member_pk(&forger.user.data.sk),
                },
                (),
            )
            .unwrap();
        let (bytes, _) = record::encode(&Record::Join {
            object: Ark(forced.object),
            old_nul: Ark(F::from(0u64)),
            account: Ark(F::from(1u64)),
            pk: Ark(persona::member_pk(&forger.user.data.sk)),
            proof: Ark(forced.proof),
        })
        .unwrap();
        let forged = Emitted {
            bytes,
            eh: record::decode(
                &record::encode(&Record::PollOpen {
                    question: String::new(),
                    options: vec![],
                    kind: PollKind::Standard,
                    target: None,
                })
                .unwrap()
                .0,
            )
            .unwrap()
            .1,
            persona: None,
        };
        assert_eq!(
            status(&mut admin, &forged),
            Status::Rejected("proof failed")
        );
        // ...nor can a valid proof be pinned to someone else's object or account.
        let honest = Member::create(keys.member.clone(), &mut rng)
            .join(&mut rng, F::from(2u64))
            .unwrap();
        let Record::Join { proof, .. } = honest else {
            unreachable!()
        };
        let (bytes, _) = record::encode(&Record::Join {
            object: Ark(forger.commitment()),
            old_nul: Ark(F::from(0u64)),
            account: Ark(F::from(2u64)),
            pk: Ark(persona::member_pk(&forger.user.data.sk)),
            proof,
        })
        .unwrap();
        let swapped = Emitted {
            bytes,
            eh: forged.eh,
            persona: None,
        };
        assert_eq!(
            status(&mut admin, &swapped),
            Status::Rejected("proof failed")
        );

        // One join per account: a second identity for alice is refused.
        let mut alice2 = new_member(&mut rng);
        let again = alice2.emit_join(&mut rng, alice_acct).unwrap();
        assert_eq!(
            status(&mut admin, &again),
            Status::Rejected("account already joined")
        );
        tick([&mut alice, &mut admin]);

        // Not banned: needs a completed sweep first.
        let post = alice
            .emit_post_pseudo(&mut rng, "hi", F::from(5u64))
            .unwrap();
        status(&mut admin, &post);
        assert!(
            alice.prove_not_banned(&mut rng, alice_acct).is_err(),
            "not swept since posting"
        );
        for m in [&mut alice, &mut admin] {
            for _ in 0..=config().settlement_barriers {
                m.barrier();
            }
        }
        while alice.scan_needed() {
            alice.prepare_scan(&mut rng, false).unwrap();
            let scan = alice.commit_scan().unwrap();
            assert_eq!(status(&mut admin, &scan), Status::Applied);
            tick([&mut alice, &mut admin]);
        }
        let proof = alice.prove_not_banned(&mut rng, alice_acct).unwrap();
        let (account, _nul, root) =
            personas_core::verify_not_banned_proof(&keys.not_banned_vk, &proof).unwrap();
        assert_eq!(account, alice_acct);
        assert!(
            admin.replica().has_produced_root(root),
            "made against the group's tree"
        );

        // The admin approves; alice resets to a fresh object and joins once more.
        let approve = admin.emit_rejoin_approve(alice_acct, Some(&proof)).unwrap();
        status(&mut alice, &approve);
        assert_eq!(alice.replica().join_counts(alice_acct), (1, 1));
        tick([&mut alice, &mut admin]);
        alice.reset_member(&mut rng).unwrap();
        let rejoin = alice.emit_join(&mut rng, alice_acct).unwrap();
        assert_eq!(
            status(&mut admin, &rejoin),
            Status::Applied,
            "the approved re-join"
        );
        assert!(alice.member_on_bulletin());
        tick([&mut alice, &mut admin]);
        // The approval is used up.
        let mut alice3 = new_member(&mut rng);
        let third = alice3.emit_join(&mut rng, alice_acct).unwrap();
        assert_eq!(
            status(&mut admin, &third),
            Status::Rejected("account already joined")
        );
        assert_eq!(fingerprint(&alice), fingerprint(&admin));
    }

    /// Two joined members, and the helpers the tests below share.
    fn joined_pair(rng: &mut StdRng, keys: &Keys, conv: &str) -> (Msg, Msg, F) {
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let conv = ConversationId(conv.into());
        let mut new_member = || {
            Msg::new(
                transport.clone(),
                conv.clone(),
                keys.replica.clone(),
                config(),
                Some(Member::create(keys.member.clone(), &mut *rng)),
            )
        };
        let (mut admin, mut alice) = (new_member(), new_member());
        let alice_acct = F::from(9002u64);
        let j = admin.emit_join(&mut *rng, F::from(9001u64)).unwrap();
        deliver(&mut alice, &j);
        let j = alice.emit_join(&mut *rng, alice_acct).unwrap();
        deliver(&mut admin, &j);
        settle(&mut [&mut admin, &mut alice]);
        (admin, alice, alice_acct)
    }

    fn status_of(m: &mut Msg, e: &Emitted) -> Status {
        deliver(m, e).unwrap().unwrap()
    }

    /// A dummy scan is accepted like any other and changes nothing about the member, so a
    /// member's scan count can be fixed whatever tickets it holds.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_a_dummy_scan_is_accepted_and_changes_nothing() {
        let mut rng = StdRng::seed_from_u64(31);
        let keys = keygen(&mut rng);
        let (mut admin, mut alice, _) = joined_pair(&mut rng, &keys, "dummy");

        // With no tickets at all, and again with one outstanding.
        for round in 0..2 {
            let before = alice.member.as_ref().unwrap().user.data.clone();
            let tickets = alice
                .member
                .as_ref()
                .unwrap()
                .user
                .num_outstanding_callbacks();
            alice.prepare_scan(&mut rng, true).unwrap();
            let scan = alice.commit_scan().unwrap();
            assert_eq!(status_of(&mut admin, &scan), Status::Applied, "round {round}");
            settle(&mut [&mut admin, &mut alice]);
            let member = alice.member.as_ref().unwrap();
            assert_eq!(member.user.data.num_interactions_since_last_scan,
                before.num_interactions_since_last_scan);
            assert_eq!(member.user.num_outstanding_callbacks(), tickets);
            assert!(!member.user.is_scanning());

            let post = alice.emit_post_anon(&mut rng, "still fine").unwrap();
            assert_eq!(status_of(&mut admin, &post), Status::Applied);
            settle(&mut [&mut admin, &mut alice]);
        }
        assert_eq!(fingerprint(&alice), fingerprint(&admin));
    }

    /// A post cannot go out mid-sweep, and one scan of a longer sweep buys no allowance:
    /// otherwise a banned member could alternate scans and posts and never reach the ban.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_a_post_cannot_interrupt_a_sweep() {
        let mut rng = StdRng::seed_from_u64(32);
        let keys = keygen(&mut rng);
        let (mut admin, mut alice, _) = joined_pair(&mut rng, &keys, "sweep");
        for text in ["one", "two"] {
            let post = alice.emit_post_anon(&mut rng, text).unwrap();
            assert_eq!(status_of(&mut admin, &post), Status::Applied);
            settle(&mut [&mut admin, &mut alice]);
        }
        for m in [&mut alice, &mut admin] {
            for _ in 0..=config().settlement_barriers {
                m.barrier();
            }
        }
        alice.prepare_scan(&mut rng, false).unwrap();
        let scan = alice.commit_scan().unwrap();
        assert_eq!(status_of(&mut admin, &scan), Status::Applied);
        let member = alice.member.as_ref().unwrap();
        assert!(member.user.is_scanning(), "two tickets need two scans");
        assert_eq!(
            member.user.data.num_interactions_since_last_scan,
            F::from(2u64),
            "an unfinished sweep does not reset the count"
        );
        settle(&mut [&mut admin, &mut alice]);
        // The client refuses this itself, so stand in for one modified not to.
        alice.member.as_mut().unwrap().user.force_clear_scan_index();
        let post = alice.emit_post_anon(&mut rng, "mid-sweep").unwrap();
        assert_eq!(
            status_of(&mut admin, &post),
            Status::Rejected("proof failed")
        );
    }

    /// Two accounts cannot share a secret key.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_two_accounts_cannot_share_a_key() {
        let mut rng = StdRng::seed_from_u64(33);
        let keys = keygen(&mut rng);
        let (mut admin, alice, _) = joined_pair(&mut rng, &keys, "clone");
        let sk = alice.member.as_ref().unwrap().user.data.sk;
        let mut member = Member::create(keys.member.clone(), &mut rng);
        member.user = zk_callbacks::generic::user::User::create(
            personas_core::circuits::MsgUser {
                sk,
                ..Default::default()
            },
            &mut rng,
        );
        let mut clone = Msg::new(
            Arc::new(MockTransport::new()),
            ConversationId("clone".into()),
            keys.replica.clone(),
            config(),
            Some(member),
        );
        let j = clone.emit_join(&mut rng, F::from(9003u64)).unwrap();
        assert_eq!(
            status_of(&mut admin, &j),
            Status::Rejected("public key belongs to another account")
        );
    }

    /// A reset keeps the secret key, and approving it retires the object given up, so the
    /// member cannot keep a second object a ban would miss.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_a_reset_keeps_the_key_and_retires_the_old_object() {
        let mut rng = StdRng::seed_from_u64(34);
        let keys = keygen(&mut rng);
        let (mut admin, mut alice, account) = joined_pair(&mut rng, &keys, "reset");
        let old = alice.member.as_ref().unwrap().user.clone();
        let proof = alice.prove_not_banned(&mut rng, account).unwrap();
        let approve = admin.emit_rejoin_approve(account, Some(&proof)).unwrap();
        assert_eq!(status_of(&mut alice, &approve), Status::Applied);
        admin.barrier();
        alice.barrier();

        alice.reset_member(&mut rng).unwrap();
        assert_eq!(alice.member.as_ref().unwrap().user.data.sk, old.data.sk);
        let rejoin = alice.emit_join(&mut rng, account).unwrap();
        assert_eq!(status_of(&mut admin, &rejoin), Status::Applied);
        admin.barrier();
        alice.barrier();

        alice.member.as_mut().unwrap().user = old;
        let post = alice.emit_post_anon(&mut rng, "from the old object").unwrap();
        assert_eq!(
            status_of(&mut admin, &post),
            Status::Rejected("nullifier already spent")
        );
    }

    /// A ban on a settled pseudonymous post still reaches its author: the pseudonym stays
    /// marked, and its next post is flagged and carries the ban to the member's object.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_a_ban_follows_a_pseudonym_past_settlement() {
        let mut rng = StdRng::seed_from_u64(35);
        let keys = keygen(&mut rng);
        let (mut admin, mut alice, _) = joined_pair(&mut rng, &keys, "retarget");
        let context = F::from(0x7Au64);
        let old = alice.emit_post_pseudo(&mut rng, "old", context).unwrap();
        assert_eq!(status_of(&mut admin, &old), Status::Applied);
        for m in [&mut admin, &mut alice] {
            for _ in 0..=config().settlement_barriers {
                m.barrier();
            }
        }
        let settled = |m: &Msg, eh| m.replica().derived().outstanding[eh].settled;
        assert!(settled(&admin, &old.eh));

        let ban = admin.emit_ban(old.eh).unwrap();
        assert_eq!(status_of(&mut alice, &ban), Status::Applied);
        let flagged = |m: &Msg, eh: &Eh| {
            m.replica()
                .log()
                .iter()
                .find(|e| e.eh == *eh)
                .is_some_and(|e| e.flagged)
        };
        assert!(flagged(&admin, &old.eh), "the old post is flagged at once");

        let new = alice.emit_post_pseudo(&mut rng, "new", context).unwrap();
        assert_eq!(status_of(&mut admin, &new), Status::Applied);
        assert!(flagged(&admin, &new.eh), "and so is the next one");
        settle(&mut [&mut admin, &mut alice]);
        assert!(settled(&admin, &new.eh), "called at once, with the ban");

        while alice.scan_needed() {
            alice.prepare_scan(&mut rng, false).unwrap();
            let scan = alice.commit_scan().unwrap();
            assert_eq!(status_of(&mut admin, &scan), Status::Applied);
            settle(&mut [&mut admin, &mut alice]);
        }
        assert_eq!(alice.member().unwrap().user.data.banned, F::from(1));
    }

    /// A ticket waits for a ban poll opened in time, so the clock cannot run out on it,
    /// and a poll that closes takes no more ballots.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_a_ban_poll_holds_its_ticket_and_closes() {
        let mut rng = StdRng::seed_from_u64(36);
        let keys = keygen(&mut rng);
        let (mut admin, mut alice, _) = joined_pair(&mut rng, &keys, "hold");
        let post = alice.emit_post_anon(&mut rng, "text").unwrap();
        assert_eq!(status_of(&mut admin, &post), Status::Applied);
        for m in [&mut admin, &mut alice] {
            for _ in 0..config().settlement_barriers - 1 {
                m.barrier();
            }
        }
        let poll = admin
            .emit_poll(
                "ban?",
                render::ban_poll_options(),
                PollKind::Ban,
                Some(post.eh),
            )
            .unwrap();
        status_of(&mut alice, &poll);
        let ballot = admin.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap();
        status_of(&mut alice, &ballot);
        settle(&mut [&mut admin, &mut alice]);
        let ticket = |m: &Msg| m.replica().derived().outstanding[&post.eh].clone();
        assert!(!ticket(&admin).settled, "past its window, and still held");
        for m in [&mut admin, &mut alice] {
            m.barrier();
        }
        assert!(ticket(&admin).banned && ticket(&admin).settled, "the ban landed");
        assert_eq!(fingerprint(&alice), fingerprint(&admin));

        let late = alice.emit_vote(&mut rng, poll.eh, 1).unwrap();
        assert_eq!(status_of(&mut admin, &late), Status::Rejected("poll closed"));
        assert_eq!(admin.replica().poll(&poll.eh).unwrap().ban_tally(), (1, 0));
    }

    /// A vote does not wait for the member's last action to settle, and being proved from
    /// the object before it changes nothing: same pseudonym, so still one ballot.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_a_vote_does_not_wait_for_a_post_to_settle() {
        let mut rng = StdRng::seed_from_u64(39);
        let keys = keygen(&mut rng);
        let (mut admin, mut alice, _) = joined_pair(&mut rng, &keys, "vote-now");
        let poll = admin
            .emit_poll("q", vec!["a".into(), "b".into()], PollKind::Standard, None)
            .unwrap();
        status_of(&mut alice, &poll);

        let post = alice.emit_post_anon(&mut rng, "text").unwrap();
        status_of(&mut admin, &post);
        assert!(!alice.is_settled() && alice.can_prove_identity());
        let first = alice.emit_vote(&mut rng, poll.eh, 0).unwrap();
        assert_eq!(status_of(&mut admin, &first), Status::Applied);
        assert!(!alice.is_settled(), "voting left the newest object in place");

        settle(&mut [&mut admin, &mut alice]);
        let second = alice.emit_vote(&mut rng, poll.eh, 1).unwrap();
        status_of(&mut admin, &second);
        let counts = admin.replica().poll(&poll.eh).unwrap().counts();
        assert_eq!(counts.get(&0), Some(&1), "the first ballot stands");
        assert_eq!(counts.get(&1), None, "the second is the same member");
    }

    /// With a clock, a barrier counts as settled once a few seconds of the next have passed,
    /// so a member need not wait out a whole barrier.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_a_barrier_settles_a_few_seconds_into_the_next() {
        let mut rng = StdRng::seed_from_u64(40);
        let keys = keygen(&mut rng);
        let mut m = Msg::new(
            Arc::new(MockTransport::new()),
            ConversationId("margin".into()),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        )
        .with_heartbeat(Heartbeat::new(0, 10_000));
        m.tick(20_500);
        let join = m.emit_join(&mut rng, F::from(9201u64)).unwrap();
        deliver_at(&mut m, &join, 20_600);
        m.tick(30_500);
        assert!(!m.is_settled(), "its barrier has only just closed");
        m.tick(32_900);
        assert!(!m.is_settled(), "still inside the margin");
        m.tick(33_100);
        assert!(m.is_settled());
        let post = m.emit_post_anon(&mut rng, "text").unwrap();
        assert_eq!(deliver_at(&mut m, &post, 33_200).unwrap().unwrap(), Status::Applied);
    }

    /// A rating is one step either way, and negative feedback counts.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_ratings_are_one_step_and_can_go_down() {
        let mut rng = StdRng::seed_from_u64(37);
        let keys = keygen(&mut rng);
        let (mut admin, mut alice, _) = joined_pair(&mut rng, &keys, "rate");
        let post = alice.emit_post_anon(&mut rng, "text").unwrap();
        status_of(&mut admin, &post);
        let big = admin.emit_rate(&mut rng, post.eh, 100).unwrap();
        assert_eq!(status_of(&mut alice, &big), Status::Rejected("a rating is +1 or -1"));
        let down = admin.emit_rate(&mut rng, post.eh, -1).unwrap();
        assert_eq!(status_of(&mut alice, &down), Status::Applied);
        let ticket = &alice.replica().derived().outstanding[&post.eh];
        assert_eq!(ticket.clamped_rep(), -1);
    }

    /// The re-base. Alice proves against a root holding one of a barrier's two records,
    /// because the other reached her too late. No one else ever produced that root, so her
    /// record is lost. She gets her object back and can send again, and the group can tell
    /// that views differed.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_a_lost_record_gives_the_object_back() {
        let mut rng = StdRng::seed_from_u64(38);
        let keys = keygen(&mut rng);
        let (mut admin, mut alice, _) = joined_pair(&mut rng, &keys, "rebase");
        let barrier = admin.replica().current_barrier();
        let mut join = |account: u64| {
            let mut m = Msg::new(
                Arc::new(MockTransport::new()),
                ConversationId("other".into()),
                keys.replica.clone(),
                config(),
                Some(Member::create(keys.member.clone(), &mut rng)),
            );
            let mut rng = StdRng::seed_from_u64(account);
            m.emit_join(&mut rng, F::from(account)).unwrap()
        };
        let (on_time, late) = (join(9101), join(9102));
        status_of(&mut admin, &on_time);
        status_of(&mut alice, &on_time);
        status_of(&mut admin, &late);
        settle(&mut [&mut admin, &mut alice]);

        let before = alice.export_member_state().unwrap().unwrap();
        let lost = alice.emit_post_anon(&mut rng, "lost").unwrap();
        assert_eq!(
            status_of(&mut admin, &lost),
            Status::Buffered,
            "it names a root the group never had"
        );

        alice.replica.ingest_at(late.bytes.clone(), barrier).unwrap();
        settle(&mut [&mut admin, &mut alice]);
        for m in [&mut admin, &mut alice] {
            m.barrier();
        }
        assert_eq!(alice.take_lost(), vec![lost.eh]);
        assert_eq!(alice.export_member_state().unwrap().unwrap(), before);
        assert_eq!(admin.foreign_roots(), 1, "the admin can see views differed");

        let resent = alice.emit_post_anon(&mut rng, "resent").unwrap();
        assert_eq!(status_of(&mut admin, &resent), Status::Applied);
    }

    /// A late joiner adopts a snapshot from an inviter, TOFU-pinned (§12): with the
    /// right pin it re-derives identical roots; a wrong pin is refused.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_snapshot_late_join() {
        let mut rng = StdRng::seed_from_u64(23);
        let keys = keygen(&mut rng);
        let conv = ConversationId("late-join".into());
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());

        // One active member builds up some state.
        let mut inviter = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let join = inviter.emit_join(&mut rng, acct()).unwrap();
        deliver(&mut inviter, &join);
        settle(&mut [&mut inviter]);
        let post = inviter
            .emit_post_pseudo(&mut rng, "history", F::from(9))
            .unwrap();
        deliver(&mut inviter, &post);
        inviter.barrier();

        let snapshot = inviter.snapshot();
        let pin = snapshot.digest();

        // A joiner adopts it against the correct pin and re-derives identical roots.
        let joiner = Messenger::<OH, MH, NH>::adopt(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            None,
            snapshot.clone(),
            &pin,
        )
        .expect("adopt with the right pin");
        assert_eq!(
            fingerprint(&joiner),
            fingerprint(&inviter),
            "roots re-derived"
        );
        assert_eq!(joiner.render(), inviter.render(), "same view");

        // A wrong pin is refused.
        assert!(matches!(
            Messenger::<OH, MH, NH>::adopt(
                transport,
                conv,
                keys.replica,
                config(),
                None,
                snapshot,
                &[0u8; 32],
            ),
            Err(AdoptError::GenesisMismatch),
        ));
    }

    /// The live transport wiring: a poll sent by one messenger reaches an observer
    /// through `subscribe` + carriage + ingest (no hand-delivery).
    #[tokio::test]
    #[ignore = "generates real Groth16 keys; run with --release --ignored"]
    async fn e2e_poll_rides_the_live_transport() {
        let mut rng = StdRng::seed_from_u64(31);
        let keys = keygen(&mut rng);
        let conv = ConversationId("live".into());
        let mock = Arc::new(MockTransport::new());
        let transport: Arc<dyn Transport> = mock.clone();

        let mut sender = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        // An observer subscribes and ingests whatever the transport delivers.
        let observer = Arc::new(tokio::sync::Mutex::new(Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            None,
        )));
        let mut stream = transport.subscribe().await.unwrap();

        // Send a poll over the transport; pump the one delivered event into the observer.
        let (poll_eh, _sent) = sender
            .send_poll("live?", render::ban_poll_options(), PollKind::Ban, None)
            .await
            .unwrap();
        let event = stream.next().await.expect("the poll is delivered");
        observer.lock().await.ingest_incoming(&event);

        assert!(
            observer.lock().await.replica().poll(&poll_eh).is_some(),
            "the observer ingested the poll off the live transport"
        );
    }

    /// The **A2 + B1 milestone**: a real Groth16 `Record` converges over REAL Signal.
    ///
    /// Same shape as `e2e_poll_rides_the_live_transport`, but the mock transport is
    /// replaced by two [`PresageTransport`]s talking to the isolated self-hosted
    /// Signal-Server. The sender emits a ban poll (a real record with a real proof); the
    /// transport derives a fresh single-use PPRF message key and AEAD-seals it, then
    /// delivers it over Signal; the observer's transport re-derives the same key from
    /// the wire `MessageTag` and AEAD-opens it; and the observer's `Replica::ingest`
    /// verifies the proof and folds it — the M3 correctness demo, now over Signal.
    ///
    /// Needs the test-server **and** the TLS proxy up (deploy/signal-test-server) plus
    /// live registration, so it is `#[ignore]` even among the e2e suite. Run by hand:
    ///   cargo test -p personas-messenger --release -- --ignored --nocapture \
    ///     e2e_record_converges_over_signal
    ///
    /// Uses a **multi-thread** runtime: presage/libsignal pump their websockets with
    /// `tokio::spawn`, which a current-thread runtime (the `#[tokio::test]` default,
    /// unlike `#[tokio::main]`) starves — registration then fails with a reqwest error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn e2e_record_converges_over_signal() {
        use transport_presage::PresageTransport;

        let mut rng = StdRng::seed_from_u64(41);
        let keys = keygen(&mut rng);
        let conv = ConversationId("personas-signal".into());

        // Two throwaway accounts (numbers varied per run so a long-lived server never
        // sees a stale account) sharing one sender key.
        let suffix = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 10_000) as u16;
        let tmp = tempfile::tempdir().unwrap();
        let db_a = tmp.path().join("a.db3").to_string_lossy().into_owned();
        let db_b = tmp.path().join("b.db3").to_string_lossy().into_owned();
        let a_aci = PresageTransport::register(&db_a, &format!("+1202555{suffix:04}"))
            .await
            .unwrap();
        let b_aci = PresageTransport::register(&db_b, &format!("+1203555{suffix:04}"))
            .await
            .unwrap();
        let shared = PresageTransport::create_group_secret();

        let a_transport: Arc<dyn Transport> = Arc::new(
            PresageTransport::start(db_a, vec![b_aci], shared.clone(), conv.clone(), None)
                .await
                .unwrap(),
        );
        let b_transport: Arc<dyn Transport> = Arc::new(
            PresageTransport::start(db_b, vec![a_aci], shared, conv.clone(), None)
                .await
                .unwrap(),
        );

        let mut sender = Msg::new(
            a_transport,
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let observer = Arc::new(tokio::sync::Mutex::new(Msg::new(
            b_transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            None,
        )));

        // Subscribe B before A sends — the transport broadcasts to current subscribers.
        let mut stream = b_transport.subscribe().await.unwrap();

        // emit (folds into A's own replica) then broadcast separately, so a post-send
        // websocket-teardown race in presage (delivery has already succeeded) does not
        // fail the test — B's ingest is the source of truth.
        let emitted = sender
            .emit_poll("ban?", render::ban_poll_options(), PollKind::Ban, None)
            .unwrap();
        let poll_eh = emitted.eh;
        if let Err(err) = sender.broadcast(&emitted).await {
            eprintln!("broadcast returned {err:?} — delivery may still have succeeded; checking B");
        }

        let event = tokio::time::timeout(std::time::Duration::from_secs(45), stream.next())
            .await
            .expect("timed out waiting for the record to arrive over Signal")
            .expect("the transport stream ended before delivering the record");
        observer.lock().await.ingest_incoming(&event);

        assert!(
            observer.lock().await.replica().poll(&poll_eh).is_some(),
            "the observer ingested the poll off REAL Signal and its replica converged"
        );
    }
}
