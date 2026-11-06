//! `personas-bench` — the evaluation's micro-benchmarks for serverless Personas.
//!
//! Runs every operation through the same engine code the Desktop app runs
//! (`personas-messenger` over `personas-bulletin`), at the production tree heights, with
//! the production proving keys, and reports per operation:
//!
//!   prove          proof generation on the client (witness + Groth16 proof)
//!   verify         the proof check alone, as a receiving member's replica makes it
//!   handle         a receiving member's replica taking the record in: decode, verify,
//!                  order and apply (the serverless counterpart of "server verification
//!                  and message handling")
//!   self_ingest    the sender folding its own record into its own replica
//!   bytes          the record (or proof) size on the wire
//!
//! plus the R1CS size of every circuit, and the moderation path: invoking a callback at a
//! settlement barrier ("post callback") and the epoch update that follows.
//!
//! Usage (release build — debug timings are meaningless):
//!
//!   cargo run --release -p personas-bench -- --keys <dir> [--iters 20] [--warmup 2]
//!       [--label modern] [--out bench-results.json] [--only op,op] [--skip-constraints]
//!
//! `--server` instead runs the server-based implementation (validation server, Privacy
//! Pass tickets, folded scans) on this machine for comparison; see `server.rs`.
//!
//! `--keys` is the directory holding `params/serverless-merkle/merkle_groth16_keys.bin`
//! — the same directory the app is given (~/.personas-demo-keys, or the packaged app's
//! `personas-keys`). Keys are generated there if absent (slow at height 32).

mod constraints;
mod fold;
mod server;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use personas_bulletin::merkle::params::ensure_merkle_keys;
use personas_bulletin::replica::record::PollKind;
use personas_bulletin::replica::{Config, ReplicaKeys, SETTLE_LAG};
use personas_core::{F, PreparedVk};
use personas_messenger::{Emitted, Member, MemberKeys, Messenger, carriage};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Serialize;
use transport_api::{ConversationId, Incoming, MessageId, Transport};
use transport_mock::MockTransport;

/// The production heights (`personas-node`'s `Engine32`).
type Engine = Messenger<32, 32, 32>;

// --- arguments ---------------------------------------------------------------------------

struct Args {
    keys: Option<PathBuf>,
    iters: usize,
    warmup: usize,
    label: String,
    out: PathBuf,
    only: Option<Vec<String>>,
    skip_constraints: bool,
    history: usize,
    /// Run the Nova folding sweep instead of the per-operation benchmarks.
    fold: bool,
    fold_batches: Vec<usize>,
    fold_ks: Vec<usize>,
    /// Run the server-based implementation instead (`server.rs`).
    server: bool,
    server_dir: PathBuf,
    /// Callbacks the server-based run answers by scanning and by folding.
    callbacks: usize,
    /// Drive a validation server that is already running, not one started here.
    server_url: Option<url::Url>,
    /// Load-test the server instead of measuring one operation at a time.
    load: bool,
    load_requests: usize,
    load_concurrency: Vec<usize>,
}

fn parse_args() -> Args {
    let mut args = Args {
        keys: None,
        iters: 20,
        warmup: 2,
        label: "unlabelled".into(),
        out: PathBuf::from("bench-results.json"),
        only: None,
        skip_constraints: false,
        history: 0,
        fold: false,
        fold_batches: vec![1, 2, 4, 8, 16],
        fold_ks: vec![1, 2, 4, 8, 16, 32, 64],
        server: false,
        server_dir: server::default_work_dir(),
        callbacks: 16,
        server_url: None,
        load: false,
        load_requests: 128,
        load_concurrency: vec![1, 4, 16, 64],
    };
    let list = |v: String, flag: &str| -> Vec<usize> {
        v.split(',')
            .map(|x| {
                x.trim()
                    .parse()
                    .unwrap_or_else(|_| usage(&format!("bad {flag}")))
            })
            .collect()
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .unwrap_or_else(|| usage(&format!("{flag} needs a value")))
        };
        match flag.as_str() {
            "--keys" => args.keys = Some(PathBuf::from(value())),
            "--iters" => args.iters = value().parse().unwrap_or_else(|_| usage("bad --iters")),
            "--warmup" => args.warmup = value().parse().unwrap_or_else(|_| usage("bad --warmup")),
            "--label" => args.label = value(),
            "--out" => args.out = PathBuf::from(value()),
            "--only" => args.only = Some(value().split(',').map(str::to_string).collect()),
            "--skip-constraints" => args.skip_constraints = true,
            "--history" => {
                args.history = value().parse().unwrap_or_else(|_| usage("bad --history"))
            }
            "--fold" => args.fold = true,
            "--fold-batches" => args.fold_batches = list(value(), "--fold-batches"),
            "--fold-k" => args.fold_ks = list(value(), "--fold-k"),
            "--server" => args.server = true,
            "--server-dir" => args.server_dir = PathBuf::from(value()),
            "--callbacks" => {
                args.callbacks = value().parse().unwrap_or_else(|_| usage("bad --callbacks"))
            }
            "--server-url" => {
                args.server_url = Some(
                    value()
                        .parse()
                        .unwrap_or_else(|_| usage("bad --server-url")),
                )
            }
            "--load" => args.load = true,
            "--load-requests" => {
                args.load_requests = value()
                    .parse()
                    .unwrap_or_else(|_| usage("bad --load-requests"))
            }
            "--load-concurrency" => args.load_concurrency = list(value(), "--load-concurrency"),
            "-h" | "--help" => usage(""),
            other => usage(&format!("unknown argument {other}")),
        }
    }
    args
}

fn usage(problem: &str) -> ! {
    if !problem.is_empty() {
        eprintln!("personas-bench: {problem}\n");
    }
    eprintln!(
        "usage: personas-bench --keys <dir> [--iters N] [--warmup N] [--label NAME]\n\
         \x20                     [--out FILE] [--only op,op,...] [--skip-constraints]\n\
         \x20                     [--history N]   (pre-fill N records of group history)\n\
         \x20      personas-bench --keys <dir> --fold [--fold-batches 1,2,4,8,16]\n\
         \x20                     [--fold-k 1,2,4,8,16,32,64] [--iters N] [--out FILE]\n\
         \x20                     (Nova-folded scans of k callbacks, N per fold step)\n\
         \x20      personas-bench --server [--history N] [--callbacks K] [--iters N]\n\
         \x20                     [--server-dir DIR] [--server-url URL] [--out FILE]\n\
         \x20                     (server-based: proved posts, Privacy Pass, scan vs fold;\n\
         \x20                     with --server-url, against that server, not a local one)\n\
         \x20      personas-bench --server --load [--load-requests N]\n\
         \x20                     [--load-concurrency 1,4,16,64] [--server-url URL] [--out FILE]\n\
         \x20                     (how many posts per second the server handles)\n\
         ops: {}",
        OPS.join(", ")
    );
    std::process::exit(if problem.is_empty() { 0 } else { 2 })
}

const OPS: &[&str] = &[
    "join",
    "anon_post",
    "pseudo_post",
    "rate_limited_post",
    "authorship",
    "vote",
    "rating",
    "badge_request",
    "badge_proof",
    "scan",
    "not_banned",
    "moderation",
];

// --- statistics ----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize)]
struct Summary {
    n: usize,
    mean_ms: f64,
    median_ms: f64,
    stdev_ms: f64,
    p95_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

fn summarize(samples_us: &[u64]) -> Option<Summary> {
    if samples_us.is_empty() {
        return None;
    }
    let mut ms: Vec<f64> = samples_us.iter().map(|&us| us as f64 / 1000.0).collect();
    ms.sort_by(f64::total_cmp);
    let n = ms.len();
    let mean = ms.iter().sum::<f64>() / n as f64;
    let var = if n > 1 {
        ms.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    let pct = |p: f64| ms[((p * (n - 1) as f64).round() as usize).min(n - 1)];
    Some(Summary {
        n,
        mean_ms: mean,
        median_ms: pct(0.5),
        stdev_ms: var.sqrt(),
        p95_ms: pct(0.95),
        min_ms: ms[0],
        max_ms: ms[n - 1],
    })
}

/// One operation's raw samples (microseconds), before summarizing.
#[derive(Default)]
struct Samples {
    prove: Vec<u64>,
    verify: Vec<u64>,
    handle: Vec<u64>,
    self_ingest: Vec<u64>,
    bytes: Vec<usize>,
    // Moderation only.
    invoke_per_callback: Vec<u64>,
    epoch_update: Vec<u64>,
}

#[derive(Serialize)]
struct OpResult {
    prove: Option<Summary>,
    verify: Option<Summary>,
    handle: Option<Summary>,
    self_ingest: Option<Summary>,
    bytes_mean: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invoke_per_callback: Option<Summary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch_update: Option<Summary>,
}

impl Samples {
    fn result(&self) -> OpResult {
        OpResult {
            prove: summarize(&self.prove),
            verify: summarize(&self.verify),
            handle: summarize(&self.handle),
            self_ingest: summarize(&self.self_ingest),
            bytes_mean: (!self.bytes.is_empty())
                .then(|| self.bytes.iter().sum::<usize>() as f64 / self.bytes.len() as f64),
            invoke_per_callback: summarize(&self.invoke_per_callback),
            epoch_update: summarize(&self.epoch_update),
        }
    }
}

fn micros(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

// --- the group under test ------------------------------------------------------------------

/// A small group: `alice` performs the measured operations, `bob` is the receiving member
/// whose replica verifies and applies them (and the admin), `carol` posts for moderation.
struct Group {
    alice: Engine,
    bob: Engine,
    carol: Engine,
    rng: StdRng,
    member_keys: MemberKeys,
    replica_keys: ReplicaKeys,
    conv: ConversationId,
    transport: Arc<dyn Transport>,
    next_account: u8,
    authorship_vk: PreparedVk,
    badge_vk: PreparedVk,
    not_banned_vk: PreparedVk,
}

fn incoming(conv: &ConversationId, bytes: &[u8]) -> Incoming {
    let carried = carriage::encode(bytes);
    Incoming::Message {
        id: MessageId("bench".into()),
        conversation: conv.clone(),
        sender: "peer".into(),
        body: carried.body,
        reply_to: None,
        attachments: carried.attachment.into_iter().collect(),
        received_at: 0,
    }
}

impl Group {
    fn new(keys_dir: &std::path::Path) -> Self {
        let started = Instant::now();
        let keys = ensure_merkle_keys(keys_dir).unwrap_or_else(|e| {
            eprintln!(
                "could not load or generate keys in {}: {e}",
                keys_dir.display()
            );
            std::process::exit(1)
        });
        eprintln!("keys loaded in {:.1}s", started.elapsed().as_secs_f64());
        let member_keys = MemberKeys::from_server_keys(&keys);
        let replica_keys = ReplicaKeys::from_server_keys(&keys);
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let conv = ConversationId("bench".into());
        let mut rng = StdRng::seed_from_u64(0x5eed);
        let engine = |rng: &mut StdRng| {
            Engine::new(
                transport.clone(),
                conv.clone(),
                replica_keys.clone(),
                Config::fast(),
                Some(Member::create(member_keys.clone(), rng)),
            )
        };
        let alice = engine(&mut rng);
        let bob = engine(&mut rng);
        let carol = engine(&mut rng);
        let mut group = Self {
            alice,
            bob,
            carol,
            rng,
            member_keys,
            replica_keys,
            conv,
            transport,
            next_account: 1,
            authorship_vk: PreparedVk::new(&keys.authorship_pred_verifying_key),
            badge_vk: PreparedVk::new(&keys.badge_pred_verifying_key),
            not_banned_vk: PreparedVk::new(&keys.not_banned_pred_verifying_key),
        };
        for who in [Who::Alice, Who::Bob, Who::Carol] {
            let account = group.account();
            let rng = &mut group.rng;
            let e = match who {
                Who::Alice => group.alice.emit_join(rng, account),
                Who::Bob => group.bob.emit_join(rng, account),
                Who::Carol => group.carol.emit_join(rng, account),
            }
            .expect("join");
            group.deliver_all_but(who, &e);
        }
        group.settle_all();
        group
    }

    fn account(&mut self) -> F {
        let mut aci = [0u8; 16];
        aci[0] = self.next_account;
        aci[15] = 0xbe;
        self.next_account = self.next_account.wrapping_add(1);
        personas_core::account_field(&aci)
    }

    fn engine(&mut self, who: Who) -> &mut Engine {
        match who {
            Who::Alice => &mut self.alice,
            Who::Bob => &mut self.bob,
            Who::Carol => &mut self.carol,
        }
    }

    /// Deliver a record to every member but its sender.
    fn deliver_all_but(&mut self, sender: Who, e: &Emitted) {
        for who in [Who::Alice, Who::Bob, Who::Carol] {
            if who != sender {
                let msg = incoming(&self.conv, &e.bytes);
                let _ = self.engine(who).ingest_incoming(&msg);
            }
        }
    }

    /// Bob (the receiving member) verifies and takes in Alice's record, timed; then Carol
    /// takes it in too, untimed, so every replica stays in step.
    fn receive_timed(&mut self, e: &Emitted, s: &mut Samples) {
        let started = Instant::now();
        let verified = self.bob.replica().verify_record_proof(&e.bytes);
        if verified.is_some() {
            s.verify.push(micros(started));
        }
        assert_ne!(
            verified,
            Some(false),
            "a measured record's proof must verify"
        );
        let msg = incoming(&self.conv, &e.bytes);
        let started = Instant::now();
        let _ = self.bob.ingest_incoming(&msg);
        s.handle.push(micros(started));
        let msg = incoming(&self.conv, &e.bytes);
        let _ = self.carol.ingest_incoming(&msg);
    }

    fn record_emit(&mut self, s: &mut Samples) {
        let t = self.alice.last_op_timings();
        s.prove.push(t.prove_us);
        s.self_ingest.push(t.self_ingest_us);
        s.bytes.push(t.bytes);
    }

    fn barrier_all(&mut self, n: usize) {
        for _ in 0..n {
            self.alice.barrier();
            self.bob.barrier();
            self.carol.barrier();
        }
    }

    /// Cross barriers until the record just sent is in a root its sender can prove from.
    fn settle_all(&mut self) {
        self.barrier_all(SETTLE_LAG as usize);
    }

    /// Pre-fill the group's history with `n` records (anonymous posts from Carol, a few
    /// per barrier), so record handling is measured against a group that has been in use.
    fn prefill(&mut self, n: usize) {
        let started = Instant::now();
        for i in 0..n {
            // Bob and Carol take turns, scanning now and then as real members do (a
            // member that never scans hits the protocol's interaction cap).
            let poster = if i % 2 == 0 { Who::Bob } else { Who::Carol };
            let rng = &mut self.rng;
            let e = match poster {
                Who::Bob => self.bob.emit_post_anon(rng, "history"),
                _ => self.carol.emit_post_anon(rng, "history"),
            }
            .expect("post");
            self.deliver_all_but(poster, &e);
            self.settle_all();
            if i % 24 == 23 {
                self.barrier_all(Config::fast().settlement_barriers as usize + 1);
                for who in [Who::Bob, Who::Carol] {
                    let mut rounds = 0;
                    while self.engine(who).scan_needed() && rounds < 400 {
                        rounds += 1;
                        let rng = &mut self.rng;
                        let e = match who {
                            Who::Bob => self.bob.emit_scan(rng),
                            _ => self.carol.emit_scan(rng),
                        }
                        .expect("scan");
                        self.deliver_all_but(who, &e);
                        self.settle_all();
                    }
                }
            }
        }
        self.barrier_all(Config::fast().settlement_barriers as usize + 1);
        eprintln!(
            "history: {n} records in {:.1}s",
            started.elapsed().as_secs_f64()
        );
    }

    /// Alice posts `k` times and lets every ticket settle without scanning, so her object
    /// carries `k` outstanding callbacks; returns it with the replica's stores.
    fn fold_subject(&mut self, k: usize) -> fold::Subject {
        let started = Instant::now();
        for _ in 0..k {
            let e = self
                .alice
                .emit_post_anon(&mut self.rng, "fold")
                .expect("post");
            self.deliver_all_but(Who::Alice, &e);
            self.settle_all();
        }
        self.barrier_all(Config::fast().settlement_barriers as usize + 1);
        let member = self.alice.member().expect("alice is a member");
        let replica = self.alice.replica();
        eprintln!(
            "fold: {} outstanding callbacks after {:.1}s",
            member.user.num_outstanding_callbacks(),
            started.elapsed().as_secs_f64()
        );
        fold::Subject {
            user: member.user.clone(),
            obj: replica.obj_store().clone(),
            cbs: replica.callback_store().clone(),
        }
    }

    /// Let every outstanding ticket settle, then have Alice absorb everything with scans
    /// (each one a scan sample). Keeps her clear of the interaction cap between batches.
    fn settle_and_drain(&mut self, scans: &mut Samples) {
        self.barrier_all(Config::fast().settlement_barriers as usize + 1);
        let mut rounds = 0;
        while self.alice.scan_needed() && rounds < 400 {
            rounds += 1;
            let e = self.alice.emit_scan(&mut self.rng).expect("scan");
            self.record_emit(scans);
            self.receive_timed(&e, scans);
            self.settle_all();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Who {
    Alice,
    Bob,
    Carol,
}

// --- the operations ----------------------------------------------------------------------------

fn run_ops(args: &Args, keys_dir: &std::path::Path) -> BTreeMap<String, OpResult> {
    let wanted = |op: &str| args.only.as_ref().is_none_or(|o| o.iter().any(|w| w == op));
    let mut g = Group::new(keys_dir);
    if args.history > 0 {
        g.prefill(args.history);
    }
    let mut results: BTreeMap<String, Samples> = BTreeMap::new();
    let total = args.warmup + args.iters;
    // A sample is kept only past the warm-up iterations.
    let keep = |i: usize| i >= args.warmup;
    let mut scans = Samples::default();

    if wanted("join") {
        let mut s = Samples::default();
        for i in 0..total {
            // A brand-new member each time: one join per account.
            let mut newcomer = Engine::new(
                g.transport.clone(),
                g.conv.clone(),
                g.replica_keys.clone(),
                Config::fast(),
                Some(Member::create(g.member_keys.clone(), &mut g.rng)),
            );
            let account = g.account();
            let e = newcomer.emit_join(&mut g.rng, account).expect("join");
            let t = newcomer.last_op_timings();
            let mut tmp = Samples::default();
            g.receive_timed(&e, &mut tmp);
            let msg = incoming(&g.conv, &e.bytes);
            let _ = g.alice.ingest_incoming(&msg);
            // One barrier per join, as for posts. Without it every measured join lands
            // in the same barrier, and one that sorts before those already applied there
            // replays them all, so the measurement grew with the iteration count.
            g.barrier_all(1);
            if keep(i) {
                s.prove.push(t.prove_us);
                s.self_ingest.push(t.self_ingest_us);
                s.bytes.push(t.bytes);
                s.verify.extend(tmp.verify);
                s.handle.extend(tmp.handle);
            }
        }
        results.insert("join".into(), s);
        eprintln!("join: done");
    }

    let post_batch = |g: &mut Group,
                      name: &str,
                      emit: &mut dyn FnMut(&mut Group, usize) -> Emitted,
                      scans: &mut Samples| {
        let mut s = Samples::default();
        for i in 0..total {
            // A member must finish a sweep every NUM_INTS_BEFORE_SCAN interactions.
            if g.alice.scan_required() {
                g.settle_and_drain(scans);
            }
            let e = emit(g, i);
            let mut tmp = Samples::default();
            g.record_emit(&mut tmp);
            g.receive_timed(&e, &mut tmp);
            if keep(i) {
                s.prove.extend(tmp.prove);
                s.self_ingest.extend(tmp.self_ingest);
                s.bytes.extend(tmp.bytes);
                s.verify.extend(tmp.verify);
                s.handle.extend(tmp.handle);
            }
            // The app's barriers are 10 s, so a barrier holds a record or two, not a
            // whole batch, and a member's next action waits for its last one to settle.
            g.settle_all();
        }
        g.settle_and_drain(scans);
        eprintln!("{name}: done");
        s
    };

    if wanted("anon_post") {
        let s = post_batch(
            &mut g,
            "anon_post",
            &mut |g, _| {
                g.alice
                    .emit_post_anon(&mut g.rng, "benchmark post")
                    .expect("post")
            },
            &mut scans,
        );
        results.insert("anon_post".into(), s);
    }
    if wanted("pseudo_post") {
        let s = post_batch(
            &mut g,
            "pseudo_post",
            // A fresh unlimited pseudonym (nonce) each time, as the composer mints them.
            &mut |g, i| {
                g.alice
                    .emit_post_pseudo(&mut g.rng, "benchmark post", F::from(1_000 + i as u64))
                    .expect("pseudo post")
            },
            &mut scans,
        );
        results.insert("pseudo_post".into(), s);
    }
    if wanted("rate_limited_post") {
        let s = post_batch(
            &mut g,
            "rate_limited_post",
            &mut |g, i| {
                g.alice
                    .emit_post_pseudo_rate(
                        &mut g.rng,
                        "benchmark post",
                        F::from(77u64),
                        F::from((i % 3) as u64),
                    )
                    .expect("rate-limited post")
            },
            &mut scans,
        );
        results.insert("rate_limited_post".into(), s);
    }
    if wanted("badge_request") {
        let s = post_batch(
            &mut g,
            "badge_request",
            &mut |g, i| {
                g.alice
                    .emit_badge_request(&mut g.rng, (i % 3 + 1) as u8)
                    .expect("badge request")
            },
            &mut scans,
        );
        results.insert("badge_request".into(), s);
    }
    if wanted("vote") {
        let s = post_batch(
            &mut g,
            "vote",
            // A new poll each time (one ballot per member per poll), opened by Bob.
            &mut |g, i| {
                let poll = g
                    .bob
                    .emit_poll(
                        format!("poll {i}"),
                        vec!["yes".into(), "no".into()],
                        PollKind::Standard,
                        None,
                    )
                    .expect("poll");
                g.deliver_all_but(Who::Bob, &poll);
                g.alice.emit_vote(&mut g.rng, poll.eh, 0).expect("vote")
            },
            &mut scans,
        );
        results.insert("vote".into(), s);
    }
    if wanted("rating") {
        let s = post_batch(
            &mut g,
            "rating",
            // One rating per member per post: Bob posts, Alice rates it.
            &mut |g, _| {
                let post = g.bob.emit_post_anon(&mut g.rng, "rate me").expect("post");
                g.deliver_all_but(Who::Bob, &post);
                g.alice.emit_rate(&mut g.rng, post.eh, 1).expect("rating")
            },
            &mut scans,
        );
        results.insert("rating".into(), s);
    }

    if wanted("authorship") {
        let mut s = Samples::default();
        for i in 0..total {
            let bytes = g
                .alice
                .prove_authorship(&mut g.rng, F::from(1_000u64), F::from(1_001u64))
                .expect("authorship");
            let t = g.alice.last_op_timings();
            let started = Instant::now();
            let ok = personas_core::verify_authorship_proof(&g.authorship_vk, &bytes).is_some();
            let v = micros(started);
            assert!(ok, "an authorship proof must verify");
            if keep(i) {
                s.prove.push(t.prove_us);
                s.bytes.push(t.bytes);
                s.verify.push(v);
            }
        }
        results.insert("authorship".into(), s);
        eprintln!("authorship: done");
    }

    if wanted("badge_proof") {
        // Earn a badge first: request, admin approval, settlement, absorb.
        let (slot, value) = personas_core::badge_value("Faculty").expect("badge");
        let req = g
            .alice
            .emit_badge_request(&mut g.rng, slot as u8)
            .expect("request");
        g.deliver_all_but(Who::Alice, &req);
        let approve = g
            .bob
            .emit_badge_approve(req.eh, slot as u8)
            .expect("approve");
        g.deliver_all_but(Who::Bob, &approve);
        g.settle_all();
        g.settle_and_drain(&mut scans);
        let mut s = Samples::default();
        for i in 0..total {
            let bytes = g
                .alice
                .prove_badge(&mut g.rng, F::from(u64::from(slot)), value)
                .expect("badge proof (is the badge held?)");
            let t = g.alice.last_op_timings();
            let started = Instant::now();
            let ok = personas_core::verify_badge_proof(&g.badge_vk, &bytes).is_some();
            let v = micros(started);
            assert!(ok, "a badge proof must verify");
            if keep(i) {
                s.prove.push(t.prove_us);
                s.bytes.push(t.bytes);
                s.verify.push(v);
            }
        }
        results.insert("badge_proof".into(), s);
        eprintln!("badge_proof: done");
    }

    if wanted("not_banned") {
        // Needs a just-finished sweep.
        g.settle_and_drain(&mut scans);
        let account = g.account();
        let mut s = Samples::default();
        for i in 0..total {
            let Ok(bytes) = g.alice.prove_not_banned(&mut g.rng, account) else {
                eprintln!("not_banned: could not prove (no completed sweep?); skipping");
                break;
            };
            let t = g.alice.last_op_timings();
            let started = Instant::now();
            let ok = personas_core::verify_not_banned_proof(&g.not_banned_vk, &bytes).is_some();
            let v = micros(started);
            assert!(ok, "a not-banned proof must verify");
            if keep(i) {
                s.prove.push(t.prove_us);
                s.bytes.push(t.bytes);
                s.verify.push(v);
            }
        }
        results.insert("not_banned".into(), s);
        eprintln!("not_banned: done");
    }

    if wanted("scan") {
        // Scans come from the drains above; make sure there are enough of them.
        let mut rounds = 0;
        while scans.prove.len() < total && rounds < 4 {
            rounds += 1;
            for _ in 0..(total - scans.prove.len()) {
                let e = g.alice.emit_post_anon(&mut g.rng, "ticket").expect("post");
                g.deliver_all_but(Who::Alice, &e);
                g.settle_all();
            }
            g.settle_and_drain(&mut scans);
        }
        let mut s = Samples::default();
        let skip = args.warmup.min(scans.prove.len());
        s.prove = scans.prove[skip..].to_vec();
        s.self_ingest = scans.self_ingest[skip..].to_vec();
        s.bytes = scans.bytes[skip..].to_vec();
        s.verify = scans.verify.iter().skip(skip).copied().collect();
        s.handle = scans.handle.iter().skip(skip).copied().collect();
        results.insert("scan".into(), s);
        eprintln!("scan: done");
    }

    if wanted("moderation") {
        // An admin's permanent ban: Carol posts, Bob bans the post, one barrier later the
        // post's callback is invoked (post callback) and the epoch is updated. Carol never
        // scans, so she can keep posting.
        g.barrier_all(Config::fast().settlement_barriers as usize + 1);
        let mut s = Samples::default();
        for i in 0..total {
            let post = g
                .carol
                .emit_post_anon(&mut g.rng, "offending")
                .expect("post");
            g.deliver_all_but(Who::Carol, &post);
            let ban = g.bob.emit_ban(post.eh).expect("ban");
            g.deliver_all_but(Who::Bob, &ban);
            let before = g.bob.replica().last_settle_timings();
            g.bob.barrier();
            g.alice.barrier();
            g.carol.barrier();
            let after = g.bob.replica().last_settle_timings();
            if let Some((_, t)) = after.filter(|a| Some(*a) != before)
                && keep(i)
                && t.invoked > 0
            {
                s.invoke_per_callback
                    .push(t.invoke_us / u64::from(t.invoked));
                s.epoch_update.push(t.epoch_update_us);
            }
            g.barrier_all(SETTLE_LAG as usize - 1);
        }
        results.insert("moderation".into(), s);
        eprintln!("moderation: done");
    }

    results.into_iter().map(|(k, v)| (k, v.result())).collect()
}

// --- output ---------------------------------------------------------------------------------

#[derive(Serialize)]
struct Machine {
    label: String,
    os: &'static str,
    arch: &'static str,
    cpu: String,
    cores: usize,
    rayon_threads: Option<String>,
}

fn machine(label: &str) -> Machine {
    let cpu = std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|c| {
                c.lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
            })
        })
        .unwrap_or_else(|| "unknown".into());
    Machine {
        label: label.into(),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        cpu,
        cores: std::thread::available_parallelism().map_or(0, usize::from),
        rayon_threads: std::env::var("RAYON_NUM_THREADS").ok(),
    }
}

#[derive(Serialize)]
struct Report {
    machine: Machine,
    iterations: usize,
    warmup: usize,
    history: usize,
    constraints: BTreeMap<String, constraints::CircuitSize>,
    operations: BTreeMap<String, OpResult>,
}

fn print_table(report: &Report) {
    let ms = |s: &Option<Summary>| {
        s.as_ref()
            .map_or("—".to_string(), |s| format!("{:.1}", s.mean_ms))
    };
    let size = |op: &str| {
        let circuit = match op {
            "vote" | "rating" => "vote_or_rating",
            other => other,
        };
        report
            .constraints
            .get(circuit)
            .map_or("—".to_string(), |c| c.constraints.to_string())
    };
    println!(
        "\n{:<18} {:>9} {:>10} {:>10} {:>10} {:>10} {:>8}",
        "operation", "R1CS", "prove ms", "verify ms", "handle ms", "self ms", "bytes"
    );
    for op in OPS {
        let Some(r) = report.operations.get(*op) else {
            continue;
        };
        if *op == "moderation" {
            continue;
        }
        println!(
            "{:<18} {:>9} {:>10} {:>10} {:>10} {:>10} {:>8}",
            op,
            size(op),
            ms(&r.prove),
            ms(&r.verify),
            ms(&r.handle),
            ms(&r.self_ingest),
            r.bytes_mean.map_or("—".into(), |b| format!("{b:.0}"))
        );
    }
    if let Some(m) = report.operations.get("moderation") {
        println!(
            "\nmoderation (admin ban): post callback {} ms, update epoch {} ms",
            ms(&m.invoke_per_callback),
            ms(&m.epoch_update)
        );
    }
    println!("\n(means; medians, p95 and stdev are in the JSON)");
}

#[derive(Serialize)]
struct FoldRun {
    machine: Machine,
    iterations: usize,
    history: usize,
    fold: fold::FoldReport,
}

fn run_fold(args: &Args, keys_dir: &std::path::Path) {
    let mut g = Group::new(keys_dir);
    if args.history > 0 {
        g.prefill(args.history);
    }
    let k_max = args.fold_ks.iter().copied().max().unwrap_or(1);
    let subject = g.fold_subject(k_max);
    let report = fold::run(
        &subject,
        &args.fold_batches,
        &args.fold_ks,
        args.iters,
        &mut g.rng,
    );

    let ms = |s: &Option<Summary>| {
        s.as_ref()
            .map_or("—".to_string(), |s| format!("{:.1}", s.mean_ms))
    };
    println!(
        "\ntie-in key generation: {:.1} s",
        report.tie_in_keygen_ms / 1000.0
    );
    println!(
        "\n{:>3} {:>12} {:>12} {:>14}",
        "N", "step R1CS", "CycleFold", "preprocess s"
    );
    for s in &report.setups {
        println!(
            "{:>3} {:>12} {:>12} {:>14.1}",
            s.batch,
            s.step_constraints,
            s.cyclefold_constraints,
            s.preprocess_ms / 1000.0
        );
    }
    println!(
        "\n{:>3} {:>4} {:>6} {:>10} {:>10} {:>11} {:>10} {:>10} {:>10}",
        "N", "k", "steps", "inputs ms", "step ms", "random. ms", "prove ms", "verify ms", "bytes"
    );
    for c in &report.cells {
        println!(
            "{:>3} {:>4} {:>6} {:>10} {:>10} {:>11} {:>10} {:>10} {:>10}",
            c.batch,
            c.callbacks,
            c.steps,
            ms(&c.inputs),
            ms(&c.per_step),
            ms(&c.randomize),
            ms(&c.prove),
            ms(&c.verify),
            c.bytes
        );
    }
    let run = FoldRun {
        machine: machine(&args.label),
        iterations: args.iters,
        history: args.history,
        fold: report,
    };
    match serde_json::to_string_pretty(&run) {
        Ok(json) => match std::fs::write(&args.out, json) {
            Ok(()) => eprintln!("wrote {}", args.out.display()),
            Err(e) => eprintln!("could not write {}: {e}", args.out.display()),
        },
        Err(e) => eprintln!("could not serialize results: {e}"),
    }
}

fn main() {
    let args = parse_args();
    if args.server {
        server::run(&args, &args.server_dir, args.callbacks);
        return;
    }
    if args.fold {
        let Some(dir) = &args.keys else {
            usage("--fold needs --keys")
        };
        run_fold(&args, dir);
        return;
    }
    let constraints = if args.skip_constraints {
        BTreeMap::new()
    } else {
        eprintln!("sizing circuits...");
        constraints::circuit_sizes()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    };
    let wants_ops = args.only.as_ref().is_none_or(|o| !o.is_empty());
    let operations = match (&args.keys, wants_ops) {
        (Some(dir), true) => run_ops(&args, dir),
        (None, _) => {
            eprintln!("no --keys given: sizing circuits only");
            BTreeMap::new()
        }
        _ => BTreeMap::new(),
    };
    let report = Report {
        machine: machine(&args.label),
        iterations: args.iters,
        warmup: args.warmup,
        history: args.history,
        constraints,
        operations,
    };
    print_table(&report);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&args.out, json) {
                eprintln!("could not write {}: {e}", args.out.display());
            } else {
                eprintln!("wrote {}", args.out.display());
            }
        }
        Err(e) => eprintln!("could not serialize results: {e}"),
    }
}
