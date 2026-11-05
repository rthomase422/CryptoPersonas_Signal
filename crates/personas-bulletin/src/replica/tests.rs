//! Fast engine tests (workstream d3).
//!
//! These exercise the deterministic state machine — canonical ordering,
//! buffering, journal replay, idempotence — without a single Groth16 proof. The
//! records that carry no proof (`Join`, `PollOpen`) are enough to test the
//! *ordering* discipline, which is where convergence lives (§1/§4); the
//! proof-carrying accept rules are covered end-to-end in [`super::e2e_tests`].

use super::record::{Ark, Record, encode};
use super::{Config, Replica, Status};
use personas_core::F;

/// A concrete, small height so the const generics are pinned (the proof-free tests
/// never touch a key, so the heights are immaterial — small just keeps the
/// per-ingest rebuild's Poseidon count low in a debug build).
type TestReplica = Replica<4, 4, 4>;

/// A `Join` committing the object `x` (its value is opaque to the engine, which
/// only appends it to the tree).
fn join(x: u64) -> (Vec<u8>, super::record::Eh) {
    let rec = Record::Join {
        object: Ark(F::from(x)),
        old_nul: Ark(F::from(1_000_000 + x)),
        // Distinct accounts (one join each). No proof: these replicas trust joins.
        account: Ark(F::from(2_000_000 + x)),
        proof: Ark(Default::default()),
    };
    encode(&rec).unwrap()
}

/// A replica with placeholder keys — fine because these tests only ingest records
/// that carry no proof, so no key is ever touched.
fn replica() -> TestReplica {
    TestReplica::new(placeholder_keys(), Config::default()).trust_unproven_joins_for_tests()
}

/// A `ReplicaKeys` whose verifying keys are default/empty — never used by the
/// proof-free tests here.
fn placeholder_keys() -> super::ReplicaKeys {
    use ark_groth16::VerifyingKey;
    let vk = VerifyingKey::default();
    super::ReplicaKeys {
        standard: vk.clone(),
        pseudo: vk.clone(),
        pseudo_rate: vk.clone(),
        scan: vk.clone(),
        pseudonym_pred: vk.clone(),
        badge_request: vk.clone(),
        join: vk,
    }
}

#[test]
fn joins_converge_regardless_of_arrival_order() {
    let a = join(1);
    let b = join(2);
    let c = join(3);

    let mut roots = Vec::new();
    for order in [
        vec![&a, &b, &c],
        vec![&c, &b, &a],
        vec![&b, &a, &c],
        vec![&c, &a, &b],
    ] {
        let mut r = replica();
        for (bytes, eh) in order.iter().map(|x| (&x.0, x.1)) {
            r.ingest(bytes.clone()).unwrap();
            assert_eq!(r.status(&eh), Some(Status::Applied));
        }
        roots.push(r.obj_root());
    }
    assert!(
        roots.iter().all(|x| *x == roots[0]),
        "the canonical (ascending-eh) order makes the tree arrival-independent"
    );
}

#[test]
fn a_duplicate_record_is_ingested_once() {
    let (bytes, _eh) = join(7);
    let mut r = replica();

    assert_eq!(r.ingest(bytes.clone()).unwrap(), Status::Applied);
    let root_after_first = r.obj_root();

    // Delivered again — no second append, same root.
    assert_eq!(r.ingest(bytes.clone()).unwrap(), Status::Applied);
    assert_eq!(r.obj_root(), root_after_first);
}

#[test]
fn a_record_naming_an_unproduced_root_is_buffered_then_applied() {
    // A vote naming a poll that has not arrived is not applicable, so it never runs
    // its (here irrelevant) proof — it simply waits.
    let poll = Record::PollOpen {
        question: "ban?".into(),
        options: vec!["ban".into(), "keep".into()],
        kind: super::record::PollKind::Ban,
        target: None,
    };
    let (poll_b, poll_eh) = encode(&poll).unwrap();

    let vote = Record::Vote {
        poll: poll_eh,
        option: 0,
        proof: Ark(ark_groth16::Proof::default()),
        claimed: Ark(F::from(5)),
        obj_root: Ark(F::from(999)), // never produced
    };
    let (vote_b, vote_eh) = encode(&vote).unwrap();

    let mut r = replica();
    // Vote first: its object root was never produced (and its poll is absent), so it
    // buffers rather than crashing on the dummy proof.
    assert_eq!(r.ingest(vote_b.clone()).unwrap(), Status::Buffered);
    // The poll applies unconditionally; the vote still buffers because its named
    // object root is not one this replica produced (§5.1).
    r.ingest(poll_b).unwrap();
    assert_eq!(r.status(&poll_eh), Some(Status::Applied));
    assert_eq!(r.status(&vote_eh), Some(Status::Buffered));
}

/// A `Ban` poll with no target — enough to watch it open at a chosen barrier and
/// close on cadence, with no proof in sight.
fn ban_poll() -> (Vec<u8>, super::record::Eh) {
    encode(&Record::PollOpen {
        question: "ban?".into(),
        options: vec!["ban".into(), "keep".into()],
        kind: super::record::PollKind::Ban,
        target: None,
    })
    .unwrap()
}

#[test]
fn ingest_at_places_a_record_by_its_supplied_barrier_not_the_local_one() {
    // The d5 cadence path: even though this replica has already reached barrier 5, a
    // record whose service timestamp buckets to barrier 0 must be *placed* at barrier 0
    // — that is what makes two replicas agree on it regardless of when each received it.
    let (poll, eh) = ban_poll();
    let mut r = replica();
    r.advance_to(5);
    r.ingest_at(poll, 0).unwrap();
    assert_eq!(
        r.poll(&eh).unwrap().opened_barrier,
        0,
        "the record is bucketed by its own barrier, not the replica's current one"
    );
}

#[test]
fn an_authoritative_arrival_reconciles_a_provisional_self_fold() {
    // `ingest` (a sender's optimistic self-fold) stamps the local barrier; the later
    // service-stamped `ingest_at` of the same record replaces it — the emit-then-
    // ingest-own-echo finalisation.
    let (poll, eh) = ban_poll();
    let mut r = replica();
    r.advance_to(3);
    r.ingest(poll.clone()).unwrap(); // provisional: opened at the local barrier 3
    assert_eq!(r.poll(&eh).unwrap().opened_barrier, 3);
    r.ingest_at(poll, 0).unwrap(); // authoritative: the service stamp says barrier 0
    assert_eq!(
        r.poll(&eh).unwrap().opened_barrier,
        0,
        "the authoritative barrier wins the reconciliation"
    );
}

#[test]
fn advance_to_closes_a_ban_poll_on_cadence() {
    // The heartbeat's settle trigger: a poll opened at barrier 0 closes once the replica
    // reaches `poll_close_barriers`, and not before.
    let (poll, eh) = ban_poll();
    let config = Config::default();
    let close = config.poll_close_barriers;
    let mut r =
        Replica::<4, 4, 4>::new(placeholder_keys(), config).trust_unproven_joins_for_tests();
    r.ingest_at(poll, 0).unwrap();
    assert!(!r.poll(&eh).unwrap().closed, "open at barrier 0");

    r.advance_to(close - 1);
    assert!(!r.poll(&eh).unwrap().closed, "still open one barrier short");

    r.advance_to(close);
    assert!(
        r.poll(&eh).unwrap().closed,
        "closed once the cadence reaches the close barrier"
    );
}

#[test]
fn advance_to_is_monotone_and_idempotent() {
    let (a, a_eh) = join(21);
    let mut r = replica();
    r.ingest_at(a, 0).unwrap();
    r.advance_to(4);
    assert_eq!(r.current_barrier(), 4);
    // A stale/duplicate advance never rewinds the barrier.
    r.advance_to(2);
    assert_eq!(r.current_barrier(), 4, "advance_to never goes backwards");
    assert_eq!(r.status(&a_eh), Some(Status::Applied));
}

#[test]
fn the_journal_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!(
        "personas-replica-journal-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("log.bin");

    let (a, a_eh) = join(11);
    let (b, _) = join(12);

    let root;
    {
        let mut r = TestReplica::open(&path, placeholder_keys(), Config::default())
            .unwrap()
            .trust_unproven_joins_for_tests();
        r.ingest(a.clone()).unwrap();
        r.ingest(b.clone()).unwrap();
        root = r.obj_root();
    }

    // Reopen: the journal replays the same records into the same tree.
    let reopened = TestReplica::open(&path, placeholder_keys(), Config::default())
        .unwrap()
        .trust_unproven_joins_for_tests();
    assert_eq!(reopened.obj_root(), root, "replay reproduces the root");
    assert_eq!(reopened.status(&a_eh), Some(Status::Applied));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn checkpointed_rebuilds_match_a_full_replay_across_a_long_schedule() {
    // The rebuild resumes from per-barrier checkpoints instead of replaying from
    // genesis (module docs). Drive it through every path — on-time, slightly late,
    // older than the checkpoint window, provisional-then-authoritative, and many empty
    // barriers — and compare against a replica rebuilt from scratch. (The test build
    // also self-checks every incremental rebuild against a full replay.)
    let mut r = replica();
    let mut records = Vec::new();
    let mut place = |r: &mut TestReplica, rec: (Vec<u8>, super::record::Eh), at: u64| {
        r.ingest_at(rec.0.clone(), at).unwrap();
        records.push((at, rec.0));
    };

    place(&mut r, join(31), 0);
    r.advance_to(10);
    place(&mut r, join(32), 10); // on time
    r.advance_to(12);
    place(&mut r, join(33), 11); // one barrier late
    let (poll, poll_eh) = ban_poll();
    place(&mut r, (poll, poll_eh), 12);
    r.advance_to(150); // past the checkpoint window
    place(&mut r, join(34), 20); // far older than any checkpoint: full replay
    place(&mut r, join(35), 149);
    let (late, late_eh) = join(36);
    r.ingest(late.clone()).unwrap(); // provisional at 150...
    r.ingest_at(late.clone(), 148).unwrap(); // ...then service-stamped two barriers back
    records.push((148, late));
    r.advance_to(151);

    let fresh = TestReplica::from_records(placeholder_keys(), Config::default(), records, 151)
        .trust_unproven_joins_for_tests();
    assert_eq!(r.obj_root(), fresh.obj_root());
    assert_eq!(r.status(&late_eh), Some(Status::Applied));
    assert_eq!(
        r.poll(&poll_eh).map(|p| (p.opened_barrier, p.closed)),
        fresh.poll(&poll_eh).map(|p| (p.opened_barrier, p.closed))
    );
}

#[test]
fn a_late_joiner_catches_up_from_stripped_records() {
    // An existing replica hands its history to a newcomer with the private text
    // removed. The newcomer must end up byte-identical (same roots, same polls, keyed
    // by the same envelope hashes), and stay identical as new records arrive.
    let mut old = replica();
    old.ingest_at(join(41).0, 0).unwrap();
    let (poll, poll_eh) = encode(&Record::PollOpen {
        question: "a private question".into(),
        options: vec!["ban".into(), "keep".into()],
        kind: super::record::PollKind::Ban,
        target: None,
    })
    .unwrap();
    old.ingest_at(poll, 2).unwrap();
    old.advance_to(5);
    old.ingest_at(join(42).0, 5).unwrap();

    let history = old.catch_up_records();
    assert!(
        history
            .iter()
            .all(|(_, _, bytes)| !String::from_utf8_lossy(bytes).contains("private question")),
        "no private text is handed over"
    );

    let mut newcomer = replica();
    assert_eq!(newcomer.import_records(history.clone()), 3);
    assert_eq!(
        newcomer.import_records(history),
        0,
        "a second copy adds nothing"
    );
    newcomer.advance_to(5);
    assert_eq!(newcomer.obj_root(), old.obj_root());
    assert_eq!(
        newcomer
            .poll(&poll_eh)
            .map(|p| (p.opened_barrier, p.closed)),
        old.poll(&poll_eh).map(|p| (p.opened_barrier, p.closed)),
        "the poll keeps its identity, so later votes still find it"
    );

    // Going forward they receive the same records and stay in step.
    let (next, next_eh) = join(43);
    old.ingest_at(next.clone(), 6).unwrap();
    newcomer.ingest_at(next, 6).unwrap();
    assert_eq!(newcomer.obj_root(), old.obj_root());
    assert_eq!(newcomer.status(&next_eh), Some(Status::Applied));
}

// --- Views (§5.5) ---------------------------------------------------------------------

/// A proof-free record carrying `claim`; `n` makes it distinct.
fn claiming(n: u64, claim: Option<super::record::ViewClaim>) -> Vec<u8> {
    let rec = Record::PollOpen {
        question: format!("q{n}"),
        options: vec![],
        kind: super::record::PollKind::Standard,
        target: None,
    };
    super::record::encode_with_view(&rec, claim).unwrap().0
}

#[test]
fn equal_records_at_equal_barriers_give_equal_views_in_any_arrival_order() {
    let records = [
        (0, join(1).0),
        (1, join(2).0),
        (1, claiming(1, None)),
        (3, join(3).0),
    ];
    let mut a = replica();
    let mut b = replica();
    for (at, bytes) in &records {
        a.ingest_at(bytes.clone(), *at).unwrap();
    }
    for (at, bytes) in records.iter().rev() {
        b.ingest_at(bytes.clone(), *at).unwrap();
    }
    for barrier in 0..5 {
        assert_eq!(a.view_digest(barrier), b.view_digest(barrier));
    }
    // Each barrier that holds a record moves the digest; an empty one does not.
    assert_ne!(a.view_digest(0), a.view_digest(1));
    assert_eq!(a.view_digest(1), a.view_digest(2));
}

#[test]
fn a_withheld_record_is_detected_stays_detected_and_a_relay_heals_it() {
    let withheld = claiming(9, None);
    let shared = [(0, join(1).0), (1, join(2).0)];
    let mut a = replica();
    let mut b = replica();
    for (at, bytes) in &shared {
        a.ingest_at(bytes.clone(), *at).unwrap();
        b.ingest_at(bytes.clone(), *at).unwrap();
    }
    // The messenger delivers one record placed at barrier 1 to `a` only.
    a.ingest_at(withheld.clone(), 1).unwrap();
    a.advance_to(4);
    b.advance_to(4);
    assert_eq!(a.view_claim().unwrap().barrier, 2);

    // Each side's next record carries its claim, and reaches both sides. Each sees the
    // other's claim disagree with its own view, and its own agree.
    let from_a = claiming(1, a.view_claim());
    let from_b = claiming(2, b.view_claim());
    for r in [&mut a, &mut b] {
        r.ingest_at(from_a.clone(), 4).unwrap();
        r.ingest_at(from_b.clone(), 4).unwrap();
        let report = r.view_report();
        assert_eq!(report.mismatches.len(), 1);
        assert_eq!((report.mismatches[0].barrier, report.agreeing), (2, 1));
    }

    // The digest is a chain: records both sides later receive do not hide the split.
    for r in [&mut a, &mut b] {
        r.ingest_at(join(3).0, 4).unwrap();
        r.advance_to(7);
    }
    assert_ne!(a.view_digest(6), b.view_digest(6));

    // `a` relays what it holds from around the mismatch, and `b` catches up. (The
    // withheld record here is a proof-free poll: a join could not be relayed.)
    for (at, bytes) in a.relayable_between(0, 2) {
        b.ingest_relayed(bytes, at).unwrap();
    }
    for barrier in 0..8 {
        assert_eq!(a.view_digest(barrier), b.view_digest(barrier));
    }
    // New claims agree, and the old mismatch ages out of the window.
    let later = 7 + super::VIEW_WINDOW;
    a.advance_to(later);
    b.advance_to(later);
    let from_a = claiming(3, a.view_claim());
    for r in [&mut a, &mut b] {
        r.ingest_at(from_a.clone(), later).unwrap();
        r.advance_to(later + super::VIEW_CLAIM_LAG);
        let report = r.view_report();
        assert!(!report.diverged(), "{report:?}");
        assert_eq!(report.agreeing, 1);
    }
}

#[test]
fn a_relay_cannot_carry_a_sender_checked_record() {
    let (bytes, eh) = join(1);
    let mut r = replica();
    let status = r.ingest_relayed(bytes, 0).unwrap();
    assert!(matches!(status, Status::Rejected(_)));
    assert_eq!(r.first_barrier(&eh), None, "not even remembered");
    // A member never offers one, either.
    r.ingest_at(join(2).0, 0).unwrap();
    assert!(r.relayable_between(0, 5).is_empty());
}

#[test]
fn a_relay_cannot_move_a_record_the_service_delivered() {
    let bytes = claiming(1, None);
    let eh = super::record::Eh::of_bytes(&bytes);
    let mut r = replica();
    r.ingest_at(bytes.clone(), 2).unwrap();
    let before = r.view_digest(5);
    r.ingest_relayed(bytes, 0).unwrap();
    assert_eq!(r.first_barrier(&eh), Some(2));
    assert_eq!(r.view_digest(5), before);
}

#[test]
fn claims_too_recent_to_check_are_pending() {
    let mut r = replica();
    r.advance_to(3);
    // A claim about barrier 2 is only one barrier behind us: our own view of it may
    // still be filling in.
    let claim = super::record::ViewClaim {
        barrier: 2,
        digest: [7; 32],
    };
    r.ingest_at(claiming(1, Some(claim)), 3).unwrap();
    let report = r.view_report();
    assert_eq!((report.pending, report.diverged()), (1, false));
}

/// Audit H1/H2: a record backdated into an earlier barrier replays that barrier, and a
/// root other records already named must not stop being produced when it does.
#[test]
#[ignore = "audit H1/H2: open until proofs name settled roots"]
fn a_backdated_record_does_not_unproduce_a_root() {
    let mut r = replica();
    let a = join(1);
    r.ingest_at(a.0.clone(), 0).unwrap();
    r.advance_to(1);
    let y = join(2);
    let mut candidate = 3;
    let x = loop {
        let c = join(candidate);
        if c.1 < y.1 {
            break c;
        }
        candidate += 1;
    };
    r.ingest_at(y.0.clone(), 1).unwrap();
    let root_after_y = r.obj_root();
    assert!(r.has_produced_root(root_after_y));
    r.advance_to(2);
    assert!(r.has_produced_root(root_after_y));
    // X arrives late, stamped into barrier 1.
    r.ingest_at(x.0.clone(), 1).unwrap();
    assert!(r.has_produced_root(root_after_y));
}
