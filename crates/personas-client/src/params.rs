//! Proving keys, fetched from the server.
//!
//! The server generates every Groth16 key and the Nova parameters once at startup (see
//! `personas_core::params`) and serves them; clients hold none of this on disk. The keys
//! are large — tens of MB for the folding parameters — so a flow fetches only the key it
//! needs, at the moment it needs it.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use personas_core::{PK, circuits::NP};

use crate::PersonaClient;

/// Parameter bytes already fetched by this process, by URL. They are fixed for a server's
/// lifetime and a key is megabytes: fetching one for every proof goes unnoticed on
/// loopback but dominates over a real network.
static FETCHED: LazyLock<Mutex<HashMap<String, Arc<Vec<u8>>>>> = LazyLock::new(Default::default);

/// How long one parameter may take to download. A client's default 30 s covers the whole
/// request, body included, which the larger keys exceed on an ordinary connection.
const FETCH_TIMEOUT: Duration = Duration::from_secs(600);
const FETCH_ATTEMPTS: u32 = 5;

fn cause_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text = format!("{text}: {cause}");
        source = cause.source();
    }
    text
}

impl PersonaClient {
    /// GET `route` (once per process) and canonical-deserialize a parameter.
    ///
    /// Panics on failure: without the key there is no proof to produce, and every caller
    /// is a proving flow that cannot proceed. The message names the route so a missing
    /// server or a stale key set is obvious.
    fn fetch_param<T: CanonicalDeserialize>(&self, route: &str) -> T {
        let url = self
            .cfg
            .url(route)
            .unwrap_or_else(|e| panic!("bad parameter route: {e}"));

        let cached = FETCHED.lock().unwrap().get(url.as_str()).cloned();
        let bytes = cached.unwrap_or_else(|| {
            let bytes = Arc::new(self.download(&url, route));
            FETCHED
                .lock()
                .unwrap()
                .insert(url.to_string(), bytes.clone());
            bytes
        });

        T::deserialize_with_mode(bytes.as_slice(), Compress::No, Validate::No)
            .unwrap_or_else(|e| panic!("server returned an undecodable parameter for {route}: {e}"))
    }

    /// Download a parameter, retrying: a transfer of tens of MB through a load balancer can
    /// be cut off partway. Says why each attempt failed (reqwest's own message for a failed
    /// body is only "error decoding response body").
    fn download(&self, url: &url::Url, route: &str) -> Vec<u8> {
        let mut last = String::new();
        for attempt in 1..=FETCH_ATTEMPTS {
            let started = Instant::now();
            let result = self
                .bul
                .client
                .get(url.clone())
                .timeout(FETCH_TIMEOUT)
                .send()
                .and_then(reqwest::blocking::Response::error_for_status)
                .and_then(reqwest::blocking::Response::bytes);
            match result {
                Ok(bytes) => return bytes.to_vec(),
                Err(e) => {
                    last = cause_chain(&e.without_url());
                    eprintln!(
                        "fetching {route}: attempt {attempt} failed after {:.1}s: {last}",
                        started.elapsed().as_secs_f64()
                    );
                }
            }
        }
        panic!("could not fetch {route} from the server: {last}");
    }

    fn fetch_pk(&self, route: &str) -> PK {
        self.fetch_param(route)
    }

    /// Posting a message: the standard interaction (rate limit, not banned).
    pub fn standard_pk(&self) -> PK {
        self.fetch_pk("api/interaction/standard/proving_key")
    }

    /// Posting under a pseudonym.
    pub fn standard_pseudo_pk(&self) -> PK {
        self.fetch_pk("api/interaction/standard/pseudo/proving_key")
    }

    /// Posting under a rate-limited pseudonym.
    pub fn standard_pseudo_rate_pk(&self) -> PK {
        self.fetch_pk("api/interaction/standard/pseudor/proving_key")
    }

    /// Requesting a badge.
    pub fn badge_request_pk(&self) -> PK {
        self.fetch_pk("api/interaction/badge/request/proving_key")
    }

    /// Scanning a single callback.
    pub fn scan_pk(&self) -> PK {
        self.fetch_pk("api/interaction/scan/proving_key")
    }

    /// Nova prover/verifier parameters for a folded scan.
    pub fn fold_params(&self) -> NP {
        self.fetch_param("api/interaction/fold/proving_key")
    }

    /// The Groth16 key for the per-step circuit folded by Nova.
    pub fn fold_pk(&self) -> PK {
        self.fetch_pk("api/interaction/fold/pre_proving_key")
    }

    /// Proving a pseudonym (`pseudonym_pred`), for votes.
    pub fn pseudonym_pred_pk(&self) -> PK {
        self.fetch_pk("api/user/arbitrary_pred_proving_key")
    }

    /// Proving two pseudonyms share an author (`authorship_pred`).
    pub fn authorship_pred_pk(&self) -> PK {
        self.fetch_pk("api/user/arbitrary_pred_proving_key2")
    }

    /// Proving a badge is held under a pseudonym (`badge_pred`).
    pub fn badge_pred_pk(&self) -> PK {
        self.fetch_pk("api/user/arbitrary_pred_proving_key3")
    }

    /// Privacy Pass: blinding a requested ticket (FINDINGS O7).
    pub fn privpass_batch_pk(&self) -> PK {
        self.fetch_pk("api/privpass/batch_proving_key")
    }

    /// Privacy Pass: the issuer's VOPRF public key, needed to unblind a validated batch.
    pub fn privpass_issuer_pubkey(&self) -> ark_grumpkin::Projective {
        self.fetch_param("api/privpass/pubkey")
    }
}
