//! `--server`: the same operations through the **server-based** implementation, with both
//! of its optimizations on — precomputed tickets (Privacy Pass) and folded scans — so the
//! two designs can be compared on one machine.
//!
//! This starts the real validation server (the `server` binary built beside this one, the
//! `local` profile: an in-process mock chat, no credentials) in a work directory, drives it
//! with the real client library (`personas-client`, what the `personas` CLI runs), and reads
//! back the timings both sides already write to `json_files/<label>/` (client proving,
//! server verification). It also times each HTTP round trip itself.
//!
//! Measured, per iteration:
//!
//!   post         prove each post: client proof, server verify, round trip
//!   pp_request   offline, per ticket: client proof, server verify + blind issuance,
//!                client unblind/verify of the issued ticket
//!   pp_post      redeem a ticket to post: client redemption, server check, round trip
//!   scan         answer K callbacks one proof at a time: per scan, client + server
//!   fold         answer the same K callbacks with one Nova-folded proof
//!
//! `--history N` first posts N proved messages from other members, so the server's
//! numbers are taken with N objects on its bulletin (they should not grow with it).
//!
//! `--server-url URL` drives a validation server that is already running instead of
//! starting one, which puts a real network between client and server. The server's own
//! timings are then on that server, so only the client's and the round trips are reported.
//! Credentials go in the URL (`https://user:password@host/validator/`). Each run adds to
//! that server's bulletin.
//!
//! `--load` measures capacity instead. Every post goes through this one server, so the
//! question is how many it handles at once: for each concurrency level it sends a batch of
//! prepared requests, that many at a time, and reports posts per second and latency.
//! Proved posts are proved first, one per member (a member's next proof needs its last on
//! the bulletin), so the clients' proving is not part of what is measured.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use personas_client::{ClientConfig, Namespace, PersonaClient};
use serde::Serialize;
use url::Url;

use crate::{Args, Summary, machine, micros, summarize};

/// Posts a member can make before it must scan (`NUM_INTS_BEFORE_SCAN`, minus slack).
const POSTS_PER_MEMBER: usize = 150;
/// The most `--load-requests`: at concurrency 1 one member takes every ticket, and the
/// levels together must stay under that same cap.
const MAX_LOAD_REQUESTS: usize = 128;

#[derive(Serialize)]
struct ServerOp {
    /// The client's own computation (proof, or ticket redemption), from `json_files`.
    client: Option<Summary>,
    /// The server's check (and, for a ticket request, blind issuance), from `json_files`.
    server: Option<Summary>,
    /// One HTTP request: the server's whole handling plus the local relay.
    round_trip: Option<Summary>,
    /// Client work after the response (unblinding a ticket), from `json_files`.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_after: Option<Summary>,
}

#[derive(Serialize)]
struct ServerReport {
    machine: crate::Machine,
    implementation: &'static str,
    /// Where the server was: `local` (started here) or `remote` (`--server-url`).
    target: &'static str,
    iterations: usize,
    warmup: usize,
    history: usize,
    /// Callbacks answered by `scan` and `fold`.
    callbacks: usize,
    fold_width: usize,
    operations: std::collections::BTreeMap<String, ServerOp>,
}

/// One concurrency level of a load test.
#[derive(Serialize)]
struct LoadRun {
    op: &'static str,
    concurrency: usize,
    requests: usize,
    errors: usize,
    wall_s: f64,
    per_second: f64,
    latency: Option<Summary>,
}

#[derive(Serialize)]
struct LoadReport {
    machine: crate::Machine,
    target: &'static str,
    history: usize,
    runs: Vec<LoadRun>,
}

/// The server process, killed when dropped.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn post_json(http: &reqwest::blocking::Client, url: Url, proof: Vec<u8>) -> u64 {
    try_post_json(http, url, proof).unwrap_or_else(|e| panic!("{e}"))
}

fn try_post_json(
    http: &reqwest::blocking::Client,
    url: Url,
    proof: Vec<u8>,
) -> Result<u64, String> {
    #[derive(Serialize)]
    struct PostRequest {
        message: String,
        group_id: String,
        proof: Vec<u8>,
    }
    let start = Instant::now();
    let res = http
        .post(url)
        .json(&PostRequest {
            message: "bench".into(),
            group_id: "bench".into(),
            proof,
        })
        .send()
        .map_err(|e| format!("post request failed: {e}"))?;
    let us = micros(start);
    if !res.status().is_success() {
        return Err(format!(
            "post rejected ({}): {}",
            res.status(),
            res.text().unwrap_or_default()
        ));
    }
    Ok(us)
}

fn post_bytes(http: &reqwest::blocking::Client, url: Url, body: Vec<u8>) -> u64 {
    let start = Instant::now();
    let res = http.post(url).body(body).send().expect("request failed");
    let us = micros(start);
    assert!(
        res.status().is_success(),
        "rejected: {}",
        res.text().unwrap_or_default()
    );
    us
}

/// The durations (ms) in `json_files/<label>/<file>`, dropping the first `skip`.
fn logged(label: &str, file: &str, skip: usize) -> Vec<u64> {
    let path = Path::new("json_files").join(label).join(file);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["duration_ms"].as_f64())
        .map(|ms| (ms * 1000.0).round() as u64)
        .skip(skip)
        .collect()
}

fn start_server(repo: &Path, work: &Path, port: u16) -> Server {
    let data = work.join("server-data");
    // A fresh bulletin each run; keep only the (slow to generate) parameter cache.
    if let Ok(entries) = std::fs::read_dir(&data) {
        for e in entries.flatten() {
            if e.file_name() != "params" {
                let p = e.path();
                let _ = if p.is_dir() {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
            }
        }
    }
    std::fs::create_dir_all(&data).expect("cannot create the server data dir");
    let log = std::fs::File::create(work.join("server.log")).expect("cannot create server.log");
    // The server binary built beside this one (`cargo build --release --bin server`).
    let exe = std::env::current_exe().expect("no current executable");
    let child = Command::new(exe.with_file_name("server"))
        .current_dir(work)
        .env("PERSONAS_CONFIG", repo.join("deploy/profiles/local.toml"))
        .env("PERSONAS_BIND", format!("127.0.0.1:{port}"))
        .env("PERSONAS_DATA_DIR", &data)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("cannot start the server (cargo build --release --bin server)");
    Server(child)
}

fn wait_ready(api: &Url) {
    let http = reqwest::blocking::Client::new();
    let url = api.join("api/privpass/pubkey").unwrap();
    let start = Instant::now();
    // First start in a new data dir generates every key: minutes.
    while start.elapsed() < Duration::from_secs(3600) {
        if http
            .get(url.clone())
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            eprintln!("server up after {:.0}s", start.elapsed().as_secs_f64());
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("server did not come up; see server.log");
}

/// Hand `items` to `concurrency` workers and time the whole batch. `send` returns one
/// latency (or error) per request it made.
fn burst<T: Send>(
    op: &'static str,
    concurrency: usize,
    items: Vec<T>,
    send: impl Fn(T) -> Vec<Result<u64, String>> + Sync,
) -> LoadRun {
    let queue = Mutex::new(items);
    let results = Mutex::new((Vec::new(), 0usize));
    let start = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..concurrency {
            scope.spawn(|| {
                loop {
                    let item = queue.lock().unwrap().pop();
                    let Some(item) = item else { break };
                    let outcomes = send(item);
                    let mut results = results.lock().unwrap();
                    for outcome in outcomes {
                        match outcome {
                            Ok(us) => results.0.push(us),
                            Err(e) => {
                                if results.1 == 0 {
                                    eprintln!("{op}: first error: {e}");
                                }
                                results.1 += 1;
                            }
                        }
                    }
                }
            });
        }
    });
    let wall_s = start.elapsed().as_secs_f64();
    let (latencies, errors) = results.into_inner().unwrap();
    let run = LoadRun {
        op,
        concurrency,
        requests: latencies.len() + errors,
        errors,
        wall_s,
        per_second: latencies.len() as f64 / wall_s,
        latency: summarize(&latencies),
    };
    eprintln!(
        "{op} at concurrency {concurrency}: {:.1}/s, {errors} errors",
        run.per_second
    );
    run
}

fn run_load(
    args: &Args,
    member: &(impl Fn(&str) -> PersonaClient + Sync),
    http: &reqwest::blocking::Client,
    jsonrpc: &Url,
) -> Vec<LoadRun> {
    let total = args.load_requests;
    assert!(
        (1..=MAX_LOAD_REQUESTS).contains(&total),
        "--load-requests must be 1 to {MAX_LOAD_REQUESTS}"
    );
    let levels: Vec<usize> = args
        .load_concurrency
        .iter()
        .map(|&c| c.clamp(1, total))
        .collect();
    let members: Vec<PersonaClient> = (0..total).map(|i| member(&format!("load-{i}"))).collect();
    let mut runs = Vec::new();

    for &concurrency in &levels {
        let proofs: Vec<Vec<u8>> = members
            .iter()
            .map(|m| m.gen_cb_for_msg().expect("post failed"))
            .collect();
        runs.push(burst("post", concurrency, proofs, |proof| {
            vec![try_post_json(http, jsonrpc.clone(), proof)]
        }));
    }

    // A member's ticket stash is one file, so each worker keeps to its own member.
    for &concurrency in &levels {
        let per_member = total / concurrency;
        let workers = &members[..concurrency];
        for m in workers {
            for _ in 0..per_member {
                m.privpass_request().expect("ticket request failed");
            }
        }
        runs.push(burst(
            "pp_post",
            concurrency,
            workers.iter().collect(),
            |m| {
                (0..per_member)
                    .map(|_| {
                        let start = Instant::now();
                        m.privpass_redeem_post("bench".into(), "bench".into(), None)
                            .map(|()| micros(start))
                            .map_err(|e| e.to_string())
                    })
                    .collect()
            },
        ));
    }
    runs
}

fn write_report(out: &Path, report: &impl Serialize) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => match std::fs::write(out, json) {
            Ok(()) => eprintln!("wrote {}", out.display()),
            Err(e) => eprintln!("could not write {}: {e}", out.display()),
        },
        Err(e) => eprintln!("could not serialize results: {e}"),
    }
}

pub fn run(args: &Args, work: &Path, callbacks: usize) {
    let repo = std::env::current_dir().expect("no working directory");
    let work = if work.is_absolute() {
        work.to_path_buf()
    } else {
        repo.join(work)
    };
    std::fs::create_dir_all(&work).expect("cannot create the work dir");
    let out = if args.out.is_absolute() {
        args.out.clone()
    } else {
        repo.join(&args.out)
    };
    let (api, _server, target) = match &args.server_url {
        Some(url) => {
            let mut api = url.clone();
            if !api.path().ends_with('/') {
                api.set_path(&format!("{}/", api.path()));
            }
            (api, None, "remote")
        }
        None => {
            let port = 3700;
            let api = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
            (api, Some(start_server(&repo, &work, port)), "local")
        }
    };
    // Client and server write `json_files/` relative to their working directory.
    std::env::set_current_dir(&work).expect("cannot enter the work dir");
    wait_ready(&api);

    let clients_dir = work.join("clients");
    let _ = std::fs::remove_dir_all(&clients_dir);
    let member = |name: &str| {
        let pc = PersonaClient::new(ClientConfig::new(
            Namespace::Signal,
            api.clone(),
            clients_dir.join(name),
        ));
        pc.join().expect("join failed");
        pc
    };
    // Longer than the default 30 s: a folded scan is megabytes to upload.
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(600))
        .build()
        .expect("cannot build the HTTP client");
    let jsonrpc = api.join("api/jsonrpc").unwrap();

    // --- history: other members' proved posts --------------------------------------------
    if args.history > 0 {
        let start = Instant::now();
        let n = args.history.div_ceil(POSTS_PER_MEMBER);
        let others: Vec<PersonaClient> = (0..n).map(|i| member(&format!("history-{i}"))).collect();
        for i in 0..args.history {
            let proof = others[i % n].gen_cb_for_msg().expect("history post failed");
            post_json(&http, jsonrpc.clone(), proof);
        }
        eprintln!(
            "history: {} posts in {:.1}s",
            args.history,
            start.elapsed().as_secs_f64()
        );
    }
    let _ = std::fs::remove_dir_all("json_files");

    if args.load {
        let report = LoadReport {
            machine: machine(&args.label),
            target,
            history: args.history,
            runs: run_load(args, &member, &http, &jsonrpc),
        };
        println!(
            "\n{:<10}{:>12}{:>10}{:>8}{:>12}{:>12}{:>12}",
            "operation", "concurrency", "requests", "errors", "per second", "median ms", "p95 ms"
        );
        for r in &report.runs {
            let (median, p95) = r
                .latency
                .as_ref()
                .map_or((f64::NAN, f64::NAN), |s| (s.median_ms, s.p95_ms));
            println!(
                "{:<10}{:>12}{:>10}{:>8}{:>12.1}{:>12.1}{:>12.1}",
                r.op, r.concurrency, r.requests, r.errors, r.per_second, median, p95
            );
        }
        write_report(&out, &report);
        return;
    }

    let total = args.warmup + args.iters;
    let mut ops = std::collections::BTreeMap::new();

    // --- prove each post --------------------------------------------------------------------
    let poster = member("poster");
    let mut rt = Vec::new();
    for _ in 0..total {
        let proof = poster.gen_cb_for_msg().expect("post failed");
        rt.push(post_json(&http, jsonrpc.clone(), proof));
    }
    ops.insert(
        "post".to_string(),
        ServerOp {
            client: summarize(&logged("anon_msg", "timings.jsonl", args.warmup)),
            server: summarize(&logged("anon_msg", "verify_timings.jsonl", args.warmup)),
            round_trip: summarize(&rt[args.warmup..]),
            client_after: None,
        },
    );
    eprintln!("post: done");

    // --- Privacy Pass: request tickets offline, redeem them to post -------------------------
    let ticketed = member("ticketed");
    let mut rt = Vec::new();
    for _ in 0..total {
        let start = Instant::now();
        ticketed.privpass_request().expect("ticket request failed");
        rt.push(micros(start));
    }
    ops.insert(
        "pp_request".to_string(),
        ServerOp {
            client: summarize(&logged("pp_request", "timings.jsonl", args.warmup)),
            server: summarize(&logged("pp_issue", "verify_timings.jsonl", args.warmup)),
            round_trip: None,
            client_after: summarize(&logged("pp_unblind", "timings.jsonl", args.warmup)),
        },
    );
    let mut rt = Vec::new();
    for _ in 0..total {
        let start = Instant::now();
        ticketed
            .privpass_redeem_post("bench".into(), "bench".into(), None)
            .expect("redemption failed");
        rt.push(micros(start));
    }
    ops.insert(
        "pp_post".to_string(),
        ServerOp {
            client: summarize(&logged("pp_redeem", "timings.jsonl", args.warmup)),
            server: summarize(&logged("pp_redeem", "verify_timings.jsonl", args.warmup)),
            // The whole redeem call: load the ticket stash, redeem, request, save the stash.
            round_trip: summarize(&rt[args.warmup..]),
            client_after: None,
        },
    );
    eprintln!("privacy pass: done");

    // --- scanning K callbacks: one proof each, or one folded proof ----------------------
    let scan_url = api.join("api/interact/scan").unwrap();
    let scanner = member("scanner");
    for _ in 0..callbacks {
        let proof = scanner.gen_cb_for_msg().expect("post failed");
        post_json(&http, jsonrpc.clone(), proof);
    }
    let mut rt = Vec::new();
    while scanner.outstanding_callbacks().unwrap() > 0 || scanner.is_scanning().unwrap() {
        let proof = scanner.scan().expect("scan failed");
        rt.push(post_bytes(&http, scan_url.clone(), proof));
        if !scanner.is_scanning().unwrap() {
            break;
        }
    }
    ops.insert(
        "scan".to_string(),
        ServerOp {
            client: summarize(&logged("scan", "timings.jsonl", 0)),
            server: summarize(&logged("scan", "verify_timings.jsonl", 0)),
            round_trip: summarize(&rt),
            client_after: None,
        },
    );
    eprintln!("scan: {} callbacks one by one", rt.len());

    let fold_url = api.join("api/interact/foldscan").unwrap();
    let folder = member("folder");
    for _ in 0..callbacks {
        let proof = folder.gen_cb_for_msg().expect("post failed");
        post_json(&http, jsonrpc.clone(), proof);
    }
    let start = Instant::now();
    let proof = folder.fold().expect("fold failed");
    let client_total = micros(start);
    let rt = post_bytes(&http, fold_url, proof);
    let steps = logged("fold", "step_timings.jsonl", 0);
    let randomize = logged("fold", "proof_timings.jsonl", 0);
    ops.insert(
        "fold".to_string(),
        ServerOp {
            // Everything the client does, keys fetched over loopback included.
            client: summarize(&[client_total]),
            server: summarize(&logged("fold", "verify_timings.jsonl", 0)),
            round_trip: summarize(&[rt]),
            client_after: None,
        },
    );
    ops.insert(
        "fold_steps".to_string(),
        ServerOp {
            client: summarize(&steps),
            server: None,
            round_trip: None,
            client_after: summarize(&randomize),
        },
    );
    eprintln!("fold: {callbacks} callbacks folded");

    let report = ServerReport {
        machine: machine(&args.label),
        implementation: "server-based, Privacy Pass + folding",
        target,
        iterations: args.iters,
        warmup: args.warmup,
        history: args.history,
        callbacks,
        fold_width: personas_core::circuits::NUM_SCANS_PER_FOLD,
        operations: ops,
    };
    let f = |s: &Option<Summary>| {
        s.as_ref()
            .map_or("—".into(), |s| format!("{:.2}", s.mean_ms))
    };
    println!(
        "\n{:<14}{:>12}{:>12}{:>14}{:>14}",
        "operation", "client ms", "server ms", "round trip", "client after"
    );
    for (name, op) in &report.operations {
        println!(
            "{name:<14}{:>12}{:>12}{:>14}{:>14}",
            f(&op.client),
            f(&op.server),
            f(&op.round_trip),
            f(&op.client_after)
        );
    }
    write_report(&out, &report);
}

/// Where `--server` keeps the server's data and the clients' state between runs.
pub fn default_work_dir() -> PathBuf {
    PathBuf::from("target/server-bench")
}
