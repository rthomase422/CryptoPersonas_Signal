# The Serverless Protocol

**Status: design. Nothing here is implemented.** This is workstream **d2**: the contract that
d1 (the Merkle bulletin), d3 (the replica engine), d4 (the messenger receive loop), d5 (the
tallies) and e2 (the modified Signal client) each implement against. It is written to be read
by a cryptographer before any of them is built.

Points marked **⚠** are decisions I am making on the basis of the code, which want sign-off
before they are built on. They are collected in [Sign-off checklist](#sign-off-checklist).

For what exists today, see `ARCHITECTURE.md`. For the bugs this design has to not inherit, see
`FINDINGS.md` — especially **O10**, which is the reason this document spends so long on roots.

---

## Changes made after the security audit

Where this section and a later one disagree, this section describes the code.

- **Payloads are bound.** A post's text and labels, a ballot's option and a rating's delta are
  public inputs of their proofs, as a hash (`post_payload`, `ballot_payload`, `rating_payload`).
- **Identity.** An `Eh` hashes what a record states, not its bytes, so a re-encoded copy or a
  re-randomized proof is the same record. A scan is the exception, because nothing refers to one.
  Tampered copies are refused before they are stored (`Replica::admissible`).
- **Tickets.** A post's published ticket must match the commitment its proof covers.
- **Object tree.** A sparse tree over each commitment's own slot, one path update per insert.
- **Members.** A join carries `pk = H(sk)`. Each account has one `pk` and each `pk` one account. A
  reset keeps `sk`, and an approved re-join spends the old object's nullifier.
- **Scanning.** Scans ride the phantom and run on a public schedule, a fixed number per epoch, padded
  with dummy scans that change nothing. An interaction needs a finished sweep, a sweep resets the
  interaction count only when it ends, and the count is capped at 20.
- **Timestamps.** Anonymous records go by the service timestamp. A sender is in its own recipient
  list, and the copy it gets back moves its record to the barrier everyone else used. Joins,
  re-join approvals and admin bans are not echoed and still go by the sender's timestamp, within
  10 s of the service's.
- **Polls** are drawn from the record, and a ban poll always shows fixed wording. A poll stays open
  24 hours and refuses ballots once closed. A member's first ballot stands.
- **Ban window.** A ticket lives 48 hours (`Config::for_period_ms`). A ticket waits for a ban poll on
  it that was opened in time, so a poll cannot run out the clock, and only such a poll can hold it,
  so polls cannot hold it forever. An anonymous post settled past that is out of reach.
- **Pseudonyms.** A ban on a settled pseudonymous post moves to the newest unsettled ticket under
  the same pseudonym. If there is none the pseudonym stays marked, and its next post is flagged and
  carries the ban. Posts under a banned pseudonym are flagged on sight.
- **Ratings** are +1 or -1, one per member per post, and cannot be withdrawn. A post's total is
  clamped to `±R_MAX`, and negative totals now reach the member's reputation.
- **Admin records.** A badge approval travels under the admin's own account and every member checks
  that the sender is a group admin, as for bans and re-join approvals. §7 and §11 describe signed
  records under a configured key. This build uses the sender check instead: a key shared among
  admins could not be taken back from a demoted one, and a late joiner already trusts an admin's
  copy of the history. The cost is that a record's authority is checked on arrival, not carried in
  the record, so a late joiner cannot re-check it (§12).
- **Roots.** A proof may name only the root at the end of a closed barrier, and members prove against
  a closed barrier that has had time to settle (see Pacing; `Replica::proving_store_at`). That root depends
  on the set of records in the barrier and not on their order, so a same-barrier race strands
  nothing, and every member who received the group's records uses the same root.
- **Pacing.** A barrier counts as settled `SETTLE_MARGIN_MS` (3 s) into the next one, by the
  member's clock, so a member's object-changing records are about 3 to 13 s apart, and a sweep of
  `n` tickets takes `n` times that. A record delayed past the margin can cost someone else a record,
  which the re-base below returns. Votes and ratings spend nothing and show only who a member is, so
  they use the member's previous object while the newest settles. It has the same key and so the
  same pseudonym, which keeps them to one each. Polls, bans and approvals carry no proof and do not
  wait. A post shows as sending at once and is proved in the background.
- **Re-basing.** A member keeps the object its newest record spent. If that record is refused, or
  still waits on an unproduced root after its barrier settles, no replica will apply it, so the
  member returns to the old object and is told to send again. This state is in memory, so a restart
  in that window still strands the member until an admin approves a reset.
- **Selective delivery (§5.5).** A member who sees a settled record naming a root it never produced
  is warned (`Replica::foreign_roots`). This narrows the audit's H5 but does not close it. A record
  sent only to a victim still gives the victim a root no one else has, so their records are held
  back and recognisable until views are repaired. Repair by relay stays off by default, because a
  relay names its own barrier, and a relayer could use that to backdate a record.
- **Late join.** Imported records must hash to the identity given and pass their proofs, though a
  poll's identity covers text the copy leaves out, and a copy can still leave records out. Sender
  checks cannot be redone, and no genesis pin exists, so §12's trust in the admin stands.
- **Bundles** are accepted only from a group admin. A bundle's trust root vouches for the phantom
  certificate only, so its minter cannot forge a real member's sender certificate.
- **Topics.** A topic's context is a hash of the group and its name, so a name has one context, and
  a post displays a topic name only if its proof is in that context. Anyone can still create a new
  topic, so the limit is per name: `AllowedContexts` is not enforced.
- **Server-mode folding** spends the object it folds from. The fold's depth is still public.

Known gaps, stated for the paper:

- All members share one sender-key chain, so two sends at the same iteration reuse a message key
  and receivers can disagree about which they keep. Fixing this needs a different routing design.
- A banned member can still vote and rate. `pseudonym_pred` proves membership of any object ever in
  the tree, so a check on `banned` could be avoided with an older object. This differs from
  `F_CryptographicPersona`.
- Enforcement of a ban stays lazy: a banned member who never scans keeps up to 19 more posts.
- Self-rating cannot be detected, and no predicate reads reputation yet.
- Joins, bans and approvals use the sender's timestamp, within 10 s of the service's.
- A callback's argument is public, since its key is the ticket in the post. Own anonymous posts stay
  on the sender's device as outgoing messages, so a seized device shows authorship.

## 1. The one-line difference

In the as-a-service deployment a server holds secret keys, is the sole writer of the bulletin,
and arbitrates every dispute by construction. Serverless deletes all three. There is no server,
so **there are no secrets** — and it turns out there never really were any (§6). What replaces
the server is a rule:

> Every member runs a replica. The group chat is an ordered log of records. Each replica
> ingests the log, applies the same deterministic accept rule, and thereby computes the same
> bulletin. **The accept rule is the protocol.**

Everything below is either that rule, or a consequence of it.

The failure mode this introduces is new, but it is milder than a first look suggests, and the
distinction is the spine of the whole design. Replicas at different points in the message stream
will *transiently* disagree — someone is always a few messages behind — and that is normal, not a
bug. What must never happen is a **persistent** fork: two replicas that have ingested the *same*
records computing *different* roots. That can only come from nondeterminism in the accept rule,
which is why every "must be deterministic" below is load-bearing. Concurrency at the tip is fine;
nondeterminism is fatal.

The reason transient disagreement is survivable is the second half of the spine: **each replica
renders its own view.** There is no global state anyone must agree on before acting — a member
applies the accept rule to whatever prefix of the log they have and displays the result. Two
members briefly seeing slightly different chats is a UI condition to annotate (§5.4), not a
consensus failure to prevent. This is closer to a CRDT than to a blockchain: convergence is
eventual, and correctness does not depend on everyone being at the same point at the same instant.

---

## 2. What has to be replaced

| the server does this today | serverless answer |
|---|---|
| `SigObjStore`: object bulletin; membership witness is a **signature** by the store key (`sigstore.rs:185`) | **d1**: Merkle tree of object commitments; witness is a path, public data is the root |
| `SigRangeStore`: nonmembership by **signed ranges**, re-signed each epoch | **d1**: one indexed (sorted) Merkle tree; nonmembership is an adjacency-leaf path |
| `has_never_received_nul` — the nullifier set | replica-held set; conflicts resolved by **first-wins in the §4 linearization** |
| `RecordLog` — message id → callback commitment, and its accrued rating | derived from the log: the `Post` record carries both |
| `PollLog` / `VoteState` — tallies | derived from the log: `PollOpen` + `Vote` records (§8) |
| `ContextLog` — thread → context field element | derived: a context is a hash of the record that opened it (§8) |
| `/api/epoch` — an admin turns the epoch to force absorption | **barriers** — a settlement heartbeat, clocked by `serverReceivedTimestamp`, or a ban (§5.2, §7) |
| `/api/ban`, `/api/reputation`, `/api/approve/badge` — an admin invokes a callback | invocation is a **trigger**, not a posted leaf: derived from the log (rep, poll-ban) or authorized by a config key (`BanInvoke`, `BadgeGrant`) (§7) |
| `/api/*/proving_key` — the server serves parameters | generated locally into the existing content-addressed cache; identical inputs, identical keys |
| Privacy Pass tickets | **do not exist serverless** — locked decision; no VOPRF key holder exists |

Note what is *not* in that table: nothing the server does requires a secret it holds. That is
not an accident of the refactor — see §6.

---

## 3. Records

A record is a `personas-wire` envelope (`{v, kind, payload}`), carried as a chat message. Small
records ride inline (base64); anything over ~32 KB rides as an attachment, which in practice
means only `FoldScan`.

Serverless changes the payload of the post kinds — a `Post` must now carry **the message body**,
because there is no server to relay it and no HTTP request to carry it beside the proof — so
this is a wire break: **`personas_wire::VERSION` goes to 2.**

A record is referenced by its **envelope hash (`eh`)**, never by a messenger `MessageId`: §4
established that Signal ids are sender-set and non-unique, so any cross-reference keyed on one is
forgeable and ambiguous. `eh` is the collision-resistant hash of the CBOR envelope.

| kind | new? | payload | who accepts it |
|---|---|---|---|
| `Join` | — | `Com<F>` | always (§9) |
| `Post` | body, root | `ExecutedMethod<…,1>`, `body: String`, `obj_root` | `obj_root` is one this replica holds (§5.1); proof verifies against it; nullifier unspent |
| `PostPseudo` | body, root | + `[context, claimed]` | as above |
| `PostPseudoRate` | body, root | + `[context, claimed, i]` | as above |
| `Rate` | **new** | `target: eh`, `delta: i8`, `Predicate` proof, `claimed`, `obj_root` | proof verifies; `claimed` has not already rated `target` (§10) |
| `PollOpen` | **new** | `question`, `options`, `kind: Standard\|Ban`, `target: Option<eh>` | always |
| `Vote` | **new** | `poll: eh`, `option`, `Predicate` proof, `claimed`, `obj_root` | proof verifies under the poll's context; `claimed` has not voted (§8) |
| `BadgeRequest` | root | `ExecutedMethod<…,1>`, `[index, claimed]`, `obj_root` | proof verifies |
| `BadgeGrant` | **new ⚠** | `request: eh`, `authority_sig` | `authority_sig` verifies under a config key with `grant_badge` (§11) |
| `BanInvoke` | **new ⚠** | `target: eh`, `authority_sig` | `authority_sig` verifies under a config key with `ban` (§7) |
| `Predicate` | — | `Proof`, `Vec<F>` | verifier picks the key; the record cannot pick it |
| `Scan` | roots | `ExecutedMethod<…,0>`, `obj_root`, `cb_root` | `obj_root` is one this replica holds; `cb_root` (now a public input, §5.3) must equal the **latest barrier the verifier has reached** (§5.2) |
| `FoldScan` | roots | `FoldingProofData`, `obj_root`, `cb_root` | as above; **off by default** |
| `Snapshot` | **new** | epoch, roots, sets (§12) | trust-on-first-use from your inviter, not an authority |

`Kind::Callback` (a bare `CallbackCom`) exists in the wire today and has **no serverless use**: no
one ever posts a callback leaf (§7). No ticket kinds exist, per the locked Privacy Pass decision.

Deviations from the plan's naming: the plan said `Register`, the code says `Join`, I keep `Join`.
The plan said `BanPollOpen`; ordinary polls exist too, so it is `PollOpen` with a `kind` field.
The plan listed neither `Rate` (§10 argues it is now mandatory) nor `BanInvoke` (the admin-ban mode
restored per the redline).

---

## 4. The log and its order

The first draft of this section ordered records by `(transport timestamp, sender id, envelope
hash)`. That was wrong, and the way it was wrong is worth recording because it is the kind of
mistake that looks fine until someone attacks it.

**The timestamp we get from Signal is set by the sender, not the provider.** `transport-signal-cli`
reads `dataMessage.timestamp` (`transport-signal-cli/src/lib.rs:340`) — that is why a Signal
message id *is* a millisecond timestamp — and that field is written by the sending client. Order
the log by it and any member can **backdate a record into the past**, inserting it before records
everyone has already built on and rewriting every root computed after it. The whole log becomes
malleable by one liar. (A service-assigned `serverReceivedTimestamp` exists in the envelope and
would be safe to *bucket* by, but ordering must not hinge on it.)

**So order is by prefix, not by clock.** Every record already names the object root it was built
on (§5.1), and that root is a commitment to the set of records accepted before it. A record is
therefore cryptographically pinned to *a prefix of the log* — you cannot claim to extend a prefix
that did not exist, and you cannot slide beneath a record that committed to being after you. This
gives a **causal (partial) order** for free, and it is the order the trees already encode.

Two consequences follow, and they are the whole of §5:

- **Backdating is dead** (fixes what the timestamp version let in). The worst a member can do is
  *withhold* a record and release it late — which does not rewrite history, it opens a concurrent
  branch, visible to everyone, resolved by rule below.
- **Concurrency is real and expected.** Two records built on the same prefix are genuinely
  concurrent; the causal order does not rank them. Where a *total* order is needed — the
  nullifier double-spend rule — replicas linearize concurrent records by a deterministic tiebreak
  (ascending envelope hash). Both conflicting records are eventually visible to everyone, so every
  replica picks the same winner. A double-spend is always self-inflicted (a member spending their
  own object twice), so "first in the linearization wins, the other is dropped" costs an honest
  member nothing.

**The provider still orders *delivery*.** It can delay, withhold, or censor — move a record past
an epoch boundary, or drop a ban record so some replicas never see it. It cannot forge a proof,
mint a member, invoke a callback, or backdate (prefix-ordering closed that). That is the
serverless trust boundary: strictly smaller than the as-a-service one, which additionally learns
who sent what. Censorship resistance is a messenger property we do not try to add, but a
messenger that withholds records from some members only is detected and, for most records,
repaired by the members themselves (§5.5). ⚠

**Determinism is a correctness requirement, not a style note.** The accept rule and the
linearization tiebreak may not consult wall-clock time, an RNG, or hash-map iteration order. Two
replicas with the same records must compute the same roots or they fork — see §1.

---

## 5. Roots, and what a proof is allowed to prove against

Every proof names a root and every verifier must independently agree that root is legitimate —
but the trees change constantly and no two replicas see an append at the same instant. The
question this section answers is: *which roots does a replica accept a proof against, and how does
it cope with a prover who is ahead of or behind it?*

The two bulletins get opposite answers, and the asymmetry (§5.2's law) is the whole game. Object
membership is monotone, so old roots are safe and the object tree runs **live**. Callback
nonmembership is anti-monotone, so old roots are poison and the callback tree is **pinned** — but
pinned to *events* (a callback invocation), not to a wall clock. Epochs survive only as a
coarse settlement heartbeat (§7), no longer as the ordering mechanism (§4 replaced that) nor as
the thing a scan proves against.

### 5.1 The object tree: stale roots are safe

The object tree is append-only, and the proof against it is **membership**: "my old object is in
the tree." Membership in an append-only set is **monotone** — once true, true forever. So a
proof against an *old* root proves membership of an object that is *still* in the tree. Nothing
is lost by accepting it.

So the object root is **live, not checkpointed**: it advances with every append, a prover proves
against whatever root they currently hold, and every verifier accepts any root in a ring buffer of
the last `K` roots (config, default 256). This is what lets prefix-ordering work — a record built
on root `r` is verifiable by anyone who has `r` in their buffer, which is anyone who is at `r` or
ahead of it.

Because the root is a *public input*, the verifier has to know which root the prover used before
it can verify — it cannot discover it. So **every record that proves membership names its root
explicitly**, and the accept rule is: the named root is one I hold, then verify once against it.
Without the name, a verifier would have to attempt up to `K` Groth16 verifications per record,
which no one can afford.

This resolves the R3 question from the redline (a finalized log seemed to cap members at one
interaction per epoch). It does not: the object tree advances **tentatively within the stream**,
prefix-ordered, and because membership is monotone the tentativeness is safe. A member chains a
second interaction on the root their first one produced, immediately, without waiting for any
epoch to close. What makes this sound where a blockchain would need finality is precisely that
the predicate is monotone — a tentative membership never has to be *revoked*, only possibly
re-based onto a later root if the first is reorged out (§5.4).

The prover-behind case is the other half. If a prover names a root the verifier has **not yet
reached** (the prover is ahead), the verifier cannot reject — the record is probably fine, it just
names a future it has not seen. It **buffers** the record and retries when it catches up. Only a
root that has aged past the ring buffer with no sight of it is finally dropped.

Two things stop the ring buffer from being a rewind attack, and both are worth naming:

- A member cannot re-spend an old object, because `old_nullifier` is checked against the
  replica's **live** nullifier set (`bulletin.rs:512`), not against a root.
  The nullifier set is itself monotone, so staleness cannot help there either.
- A member cannot escape a ban by proving against a pre-ban root, because the object tree does
  not know about bans. `banned` is a field *inside the member's object*, and it changes only
  when the member **scans**. What forces them to scan is `num_interactions_since_last_scan`
  hitting `NUM_INTS_BEFORE_SCAN` (200), after which every post predicate fails
  ([circuits.rs:352](../crates/personas-core/src/circuits.rs#L352)). Bans are enforced by the
  scan, not by the object root — with a large loophole (up to 200 posts between ban and forced
  scan) that serverless closes at the *rendering* layer, not the crypto one. See §9.

**Implementation note — set-committing object tree (d1/d3), and reconciliation (deferred).**
The prose above describes the object root as *live and prefix-ordered*, which made the tree
append-order-sensitive and pushed a full canonical total-order onto the replica engine. The
implemented d1 object store instead commits to the **set** of registrations: leaves are sorted
by commitment and the tree is rebuilt over that order, so the root is a pure function of the set
(the same trick §5's nonmembership tree already uses; the in-circuit gadget is unchanged, so this
costs nothing in the proof). This makes the *final* root arrival-order-independent and removes
the tree-shape reason for a total order — the only residual ordering is **first-reveal-wins on
the nullifier**, which is not a tree property (a member re-revealing a nullifier is
double-spending or rewinding, and is refused). What a set-committing root does *not* by itself
solve is the **buffered-root window**: a proof is pinned to the root of a specific recent subset,
and two replicas that ingested the same records in different orders pass through different
intermediate subsets, so one may not hold the exact root a proof names. For now d3 keeps a
deterministic replay (ascending `eh`) so intermediate roots converge exactly and the demo path
is sound; the intended replacement — **deferred** — is **reconciliation by Bloom filter**: a
proof carries a small Bloom filter of *which* recent records its tree includes, and a verifier
reconstructs that exact set (fetching anything it is missing) and checks the pinned root. Under
the eventual-delivery assumption (every record reaches everyone) this converges efficiently; the
filter is a reconciliation *accelerator* (a false positive just forces a fetch-and-retry), not a
standalone commitment. This is the natural home for that mechanism precisely because the root is
now set-determined. ⚠

### 5.2 The callback tree: stale roots are fatal

The scan proves, per outstanding ticket, membership **XOR** nonmembership in the called-back set
(`bulletin.rs::enforce_memb_nmemb`). And **nonmembership of a growing set is
anti-monotone**: once false, it stays false, so a proof against a stale root asserts something
that *was* true and is now a lie. "This ticket has not been called" is exactly the sentence a
banned member wants to keep saying.

That is O10, stated generally. Today's implementation loses it in the most direct way possible:
the nonmembership witness is a signed range whose `epoch` is a **private witness**, never
compared to the public `cur_time`, verified under a key that `update_epoch` never rotates
(`sigrange.rs:296–321`). Archive a range, get banned, replay the range
forever.

So the callback root cannot run live. But the redline showed my first fix (checkpoint per
fixed 60 s epoch) was solving the wrong problem: the callback set only *changes* when a callback
is invoked, and invocations are rare, public events (§7) — a ban, or a settlement heartbeat.
Between them the set is frozen and any recent root is fine. Pinning to a wall clock would force a
re-fetch every 60 s for a set that changed twice all day.

So the pin is **event-driven**:

> The callback tree advances **only at a barrier** — the close of a settlement heartbeat, or a
> ban/authority invocation. A scan names the barrier it proves against (by root); a verifier
> accepts it only against **the latest barrier it has itself reached**. Between barriers the root
> is constant, so "latest" is unambiguous and no grace window is needed. A scan against a
> superseded barrier is rejected — that is the anti-monotone discipline, and it is the whole
> defense against O10.

This is where the redline's insight lands: *when a ban happens it is public, and every replica
pauses at that barrier and brings itself up to date before accepting further scans.* The
barrier is not a global lock — each replica reaches it independently as it ingests the invocation
record — but its effect is that a scan is only ever checked against a callback set that includes
every ban the checker has seen. A member cannot get a stale-set scan accepted by anyone who has
witnessed the ban.

The general law, which is the thing I would most like reviewed:

> A stale root is safe for a monotone predicate and fatal for its negation. Membership of an
> append-only set may be proved against any historical root. Nonmembership may be proved only
> against the latest root the verifier has reached.

The two subtleties this leaves are (a) a member who *has not yet* seen a ban will accept the
banned member's scan — bounded by delivery latency, and closed permanently at the next barrier
they both cross; and (b) the barrier cadence trades ban latency against scan-invalidation churn,
which is the settlement-frequency knob in §7. Both are called out for sign-off.

### 5.3 Why the Merkle bulletin closes O10 structurally

Here is the part that made this worth writing down. Today the scan circuit's callback-bulletin
public data is loaded as a **circuit constant**, and is therefore *absent from the proof's public
inputs*:

```rust
// personas-core/src/circuits.rs — get_extra_pubdata_for_scan
is_memb_data_const:  true,
is_nmemb_data_const: true,
```

`PubScanArgs::to_field_elements` skips `memb_pub`/`nmemb_pub` exactly when those flags are set
(`scan.rs:186–200`), and `PubScanArgsVar::new_variable` allocates them with
`new_constant` (`scan.rs:267–284`). The same flag exists for the object
bulletin, as an explicit parameter of `User::interact` (`user.rs:990`), and
personas passes `true` there too.

For the signature stores this is *correct*: the public data is a verification **key**, which
never changes, so baking it into the proving key costs nothing. And it is precisely why O10
bites — nothing about the callback bulletin's *contents* is pinned by the verifier. Only
`cur_time` is public, and `cur_time` is read only inside `expirable`-gated branches, which are
dead because our sole callback is `expirable: false`.

For a Merkle store the public data is a **root**, which changes on every append. Baking a root in
as a circuit constant would mean regenerating the proving key on every append, which is absurd.
So d1 has no choice: it must pass `is_memb_data_const = false` / `is_nmemb_data_const = false`,
and `memb_data: Some(root)` to `verify_interaction`. That single forced change puts the roots
into the public inputs — where **every verifying replica compares them against the roots it
computed itself**.

The epoch binding O10 asks for therefore arrives for free, and better than asked: it is not "the
witness epoch equals `cur_time`" enforced inside the circuit, it is "the root is the one I
pinned" enforced outside it, by everyone. The key-rotation half of the O10 fix becomes moot,
because there is no key.

**This does not make O10 go away.** It goes away *in serverless*, if and only if the accept rule
pins the callback root to the latest barrier (§5.2). The as-a-service deployment on the signature
stores is still exposed, and the upstream circuit fix is still owed. ⚠

### 5.4 Convergence, reorg, and what the UI has to admit

Prefix-ordering (§4) plus monotone object roots (§5.1) give a system that converges without
consensus, but the transient states are real and the client has to handle them honestly rather
than pretend they do not happen.

**Reorg of a tentative object.** A member builds interaction B on the root their interaction A
produced. If A loses a double-spend linearization, or a concurrent record orders ahead of A and
changes the root, B now names a root no one will reach. B is not *wrong* — its proof is valid
against a root that briefly existed on this member's branch — it is *orphaned*. The client detects
this (its named root aged out of everyone's buffer without being reached) and **re-bases**:
re-proves B against the current root and re-broadcasts. This is the one place the client must
track its own in-flight state carefully; §13 spells out the state machine. It is cheap because
re-basing an object-membership proof is a re-prove, not a protocol round trip.

**A ban you have not seen yet.** Until you ingest a ban record you will render the banned member's
pseudonymous posts as ordinary, and accept their scans (§5.2(a)). This is bounded by delivery and
closes at the next shared barrier. The UI should not paper over it: a post that turns out to
predate a ban the viewer later ingests is **re-rendered as flagged**, not silently deleted — the
redline's "annotate messages that might be from a since-banned person." Deleting would itself be a
covert-fork signal; flagging tells the truth about what the replica knew and when.

**Persistent disagreement is still a bug.** Everything above is *transient* — it resolves as
records propagate. If two replicas that have ingested an identical set of records render
differently, that is a determinism bug in the accept rule (§1), and the convergence test (g) has
to catch it: feed N replicas the same records in adversarially different *arrival* orders and
assert identical roots.

### 5.5 Views: detecting a messenger that shows members different records

> **Status: implemented, OFF by default** (`Messenger::with_view_checks`, the addon's
> `viewChecks` option, Desktop's `PERSONAS_VIEW_CHECKS=1`), pending review of the tagging
> cost below. With it off, records carry no claim and encode exactly as before, and relays
> are ignored.

§4 leaves one power with the messenger: it orders and delivers, so it can delay or drop a
record for *some* members only. Nothing above would notice. Two members would then compute
different states, and each would believe it was the group's.

**Every record carries its sender's view.** The envelope gains an optional field
`view: {barrier, digest}` ([`record::ViewClaim`](../crates/personas-bulletin/src/replica/record.rs)).
The digest ([`Replica::view_digest`](../crates/personas-bulletin/src/replica/mod.rs)) is a
hash chain over the barriers that hold any record. Each link commits to the previous link,
the barrier number and the envelope hashes of every record placed at that barrier, in
ascending order, whether the record was applied, buffered or rejected. The bulletin is a
deterministic function of exactly these inputs, so equal digests mean equal state.

- **Which barrier.** A sender claims `current_barrier − VIEW_CLAIM_LAG` (2). By then
  every record placed at that barrier has had at least one heartbeat to arrive. A receiver
  checks a claim only once it is itself that far past the barrier, and before that the
  claim counts as `pending`.
- **Why a chain.** Once two members' views of a barrier differ, every later digest differs
  too. A messenger that splits a group cannot quietly merge it later: it has to keep the
  two sides apart for good, and every record either side sends exposes the split (fork
  consistency, as in SUNDR).
- **Binding.** The claim is inside the envelope, so the record's `eh` covers it, and the
  payload is end-to-end encrypted, so the messenger cannot change it. A member who
  re-wraps someone else's proof under a different claim produces a second record with the
  same nullifier, and the §4 double-spend rule keeps only one. The claim is not a public
  input of the proof. Binding it in-circuit would need new circuits and keys, and buys
  nothing against the messenger.
- **Compatibility.** A record without a claim encodes byte-for-byte as before, so
  journaled `eh`s are unchanged, and a reader that predates claims ignores the field.

**Comparing.** [`Replica::view_report`] compares the claims carried by records from the
last `VIEW_WINDOW` (10) barriers with our own digests, and lists the records whose claims
disagree. A member who was briefly behind sent claims that disagree, but these age out of
the window once that member catches up. A split that persists keeps producing fresh
mismatches for as long as the other side sends anything. Desktop shows the member a
warning the first time a report turns `diverged`.

**Relaying.** For a mismatch at barrier `b`, a member re-sends every record it holds that
was placed at `b − VIEW_CLAIM_LAG ..= b`, as `PZY2:<barrier>:<base64 record>`, at most once
per record ([`Messenger::take_relays`](../crates/personas-messenger/src/lib.rs)). Claims are
made continuously, so a view that first differs at `b` most likely differs because of a
record placed shortly before it. Both sides relay, so whichever side is missing records
receives them.

- A relayed record is placed at the barrier the relay names, capped at the relay
  message's own service-stamped barrier, and it is **not authoritative**: a record we
  already hold keeps its barrier. A relayer who lies about the barrier changes only the
  receiver's view, and that shows up as a mismatch like any other split.
- A **join, re-join approval or admin ban is never relayed**
  ([`Record::relayable`](../crates/personas-bulletin/src/replica/record.rs)), and a relay
  carrying one is refused. Those records are accepted only because of who sent them over
  Signal (the joining account, a group admin), and a relay hides the sender. If the
  messenger withholds one, members detect it but cannot repair it in-band.

**Tagging (the privacy cost, and why it is off by default).** A view claim reveals which
records its sender had seen. Signal cannot read it (the payload is end-to-end encrypted),
but group members can. Desktop encrypts a group message per recipient, so a malicious
member with a modified client can send a record to one victim only. Until a relay heals
the split, every record the victim sends, anonymous posts included, carries a digest
nobody else has, and the attacker can pick out the victim's records.

This is not new in kind. Every proof-carrying record already names the object root it was
built on (§5.1), so a post or join sent to one victim only makes the victim's next records
name a root only the victim holds. Without view checks that split is also *permanent*:
nobody else can verify the victim's records, so the victim is silently cut off. View
checks make the split detectable and short-lived, but they widen the tag from posts and
joins to every record kind.

Candidate fixes, for review:

1. **Separate attestations.** Members send their claims as standalone anonymous messages
   instead of inside posts, votes and ratings. A tagged attestation then shows only that
   *some* member has view V, and is linked to nothing that member wrote.
2. **Prove against settled roots.** The replica accepts any object root in the last `K`
   (§5.1). A member who proves against a root that is a few barriers old, and that other
   members' claims have confirmed, cannot be tagged by a split shorter than that, and view
   checks catch a longer one. This also closes the pre-existing root tag. The cost: after
   posting, a member must wait until its new object is in a settled root before posting
   again.
3. **Hold anonymous sends while views disagree,** until the relays land.

**What this does and does not give.** Against a messenger that drops or delays records but
delivers relays, members detect the split and repair it. Against one that also drops the
relays, members still *detect* the split: it cannot be hidden, only kept. Detection needs
the other side to send something. A member who is completely cut off sees no
disagreement, because it sees nothing. The stronger steps, not implemented:

1. **Quorum-attested barriers.** Before applying a barrier, require a majority of members
   to attest to the same digest for it, each with a `pseudonym_pred` vote whose context is
   the barrier (one attestation per member, unlinkable across barriers). Two disjoint
   majorities cannot exist, so the messenger can no longer make two members apply
   different bans. It can still stall the group, and the stall is visible.
2. **An out-of-band check.** Comparing a short digest code in person or over another app
   (like Signal's safety numbers) catches a member the messenger has cut off entirely.

---

## 6. Nobody is holding a key (and what that costs)

The single most important thing I found reading the ticket crypto. Personas instantiates
`Cr = NoSigOTP<F>` ([types.rs:27](../crates/personas-core/src/types.rs#L27)), and in
zk-callbacks every one of these is the *same type*, a single field element:

```rust
pub type FakeSigPubkey<F>  = PlainTikCrypto<F>;
pub type FakeSigPrivkey<F> = PlainTikCrypto<F>;
pub type OTPEncKey<F>      = PlainTikCrypto<F>;
pub type NoSigOTP<F>       = PlainTikCrypto<F>;
```

with `sk_to_pk(&self) -> self.clone()`, `verify(_, _) -> true`, `type Sig = ()`, and
`encrypt(m) = m + k` (`crypto.rs:85–200`). The service's signing key is
`FakeSigPrivkey::sk()`, which is **the constant zero** (`crypto.rs:182`).
The upstream docs say so plainly: *"As signatures are not necessary in the centralized setting,
any private key can be used to verify tickets."*

So a callback ticket `tik` is one field element that is simultaneously (a) the ticket's identity,
(b) the OTP key its argument is encrypted under, and (c) the entire authority required to invoke
it. There is no signature on a call. **What restricts invocation in service mode is not
cryptography — it is that the server is the only writer of the callback bulletin.**

Serverless deletes the only writer. And the ticket travels in `cb_tik_list` inside the
`ExecutedMethod`, which every member receives. Consequences, all of them real:

- **Every member can invoke every callback, with any argument the circuit permits — including
  `BAN_FLAG`.** If invocations were messages, any single member could ban anyone.
- **Every member can burn every ticket.** A callback may be called once
  (`has_never_received_tik`). An attacker who calls each ticket the moment they see the post,
  with a harmless argument, permanently disarms moderation. The *poster* can do this to their
  own ticket, pre-emptively, which is the sharpest form.
- **Every callback argument is public**, since everyone holds the OTP key. In service mode only
  the server and the member knew them.

The first two are why §7 is written the way it is. The third is benign here (arguments are
derived from public tallies anyway) but it should be stated rather than discovered. ⚠

---

## 7. Callbacks are derived or authorized, never freely posted

**No member ever posts a callback leaf.** A leaf is `(tik, ct, epoch)` with `ct = arg + tik` — the
OTP is additive and keyless-in-practice (§6), so every replica computes it byte-identically from
public data, with no RNG. What every replica needs to agree on is therefore not *the leaf* but
*the trigger*: when, and with what argument, a given ticket is called. There are two kinds of
trigger, and the split is the answer to §6's attack surface.

**Derived triggers** carry no record at all — the replica computes them from conditions already in
the log:

- a **settlement heartbeat** retires a ticket with its accrued reputation;
- a **ban poll** that closes `yes > no` (§8) retires the target's ticket with `BAN_FLAG`.

**Authorized triggers** carry a signed record, because no condition in the log establishes them —
they are a *decision* by a named party:

- **`BanInvoke`** — an admin unilaterally bans a post. Payload `{ target, authority_sig }`; the
  accept rule invokes `BAN_FLAG` on the target's ticket iff `authority_sig` verifies under a
  config authority key holding the `ban` capability. This is the mode you asked to restore; it is
  the same mechanism as the badge issuer (§11), and the two capabilities are one config list.
- **`BadgeGrant`** — §11.

Neither kind is a *freely postable* invocation, which is the whole point. A member cannot forge a
derived trigger (the condition either holds in the log or it does not) and cannot forge an
authorized one (no signature). A member is of course free to compute a bogus leaf into *their own*
tree, and thereby compute a root no one else does — attacking only themselves. The §6 nightmares
(anyone bans anyone; anyone burns every ticket) have no record that expresses them.

### The settlement rule

A post carries exactly one callback ticket (`NUMCBS = 1`). It is called exactly once, at its
**settlement barrier** `post_epoch + W` (config `settlement_epochs`), with exactly one argument,
chosen by this precedence:

> 1. `BAN_FLAG`, if a `BanInvoke` for that post verified, **or** a ban poll naming it closed
>    `yes > no`, at any barrier up to and including settlement; else
> 2. `arg_rep(r)`, where `r` is the ratings accrued on that post — clamped to `[0, R_MAX]` (§10,
>    R8: `r` must not be allowed to reach `BAN_FLAG`); may be `arg_rep(0)`.

A ban that lands *before* settlement takes effect at that earlier barrier, not at `post_epoch+W` —
the deadline is the *latest* a ticket lives, not the only moment it can be called. Properties:

1. **One ticket, one call, one argument.** Ban strictly precedes reputation, so they cannot
   contend for the ticket (a ticket spent on reputation could never afterwards carry a ban).
2. **The outstanding set is bounded.** Every ticket is retired within `W`, including with
   `arg_rep(0)`. This is not optional: an uncalled ticket stays *in-progress* in the member's
   object forever and every future scan must carry it, so a prolific poster's scan cost would grow
   without bound. **But retiring every ticket makes every post oblige its author to eventually
   scan** — and at `NUM_SCANS_PER_FOLD = 1` that is one scan record per post (R6). This is why
   **c1 is a prerequisite of d, not a parallel nicety**: at N=1 the scan traffic doubles the chat.
   Recorded as O6-adjacent; see the parameter table and the sign-off list. ⚠
3. **You cannot ban an old post.** The ticket is gone after `W` barriers — for an *anonymous*
   post that is a hard wall. For a *pseudonymous* post it is not: `BAN_FLAG` sets `banned = 1` on
   the *member's object*, so any unspent ticket of theirs will do, and posts under one `claimed`
   pseudonym are provably one member. A ban (poll or admin) against a pseudonymous post settles
   against the newest unspent ticket under that pseudonym. This is also the general principle for
   R4: **a ban bites exactly as far as the banned activity is linkable** — fully on a pseudonym,
   not at all on unlinkable anonymous posts, which is what anonymity *means*. Choosing `W` trades
   ban reach against outstanding-set size and is as much product as crypto. ⚠

There is a partial escape from (3) worth noting: `BAN_FLAG` sets `banned = 1` on the *member's
object*, so **any** unspent ticket of that member's will do. The group cannot tell which tickets
belong to one member — that is the point of the system — **except** for posts under the same
pseudonym, which are by construction the same member. So a ban poll against a *pseudonymous*
post may be settled against the newest unspent ticket among all posts under that `claimed`
pseudonym. Against an *anonymous* post, only that post's own ticket exists, and `W` is a hard
wall. ⚠

### O3 dissolves

`FINDINGS` O3 (routes disagree about whether tickets are filed at `Time::from(0)` or the live
epoch) has no serverless analogue: **every record files its tickets at the epoch it was posted
in**, uniformly. The `expiration == def.expiration + cur_time` check
(`service.rs:208`) is then consistent by construction.

---

## 8. Polls, votes, and the tally

`PollOpen` announces a poll. Its **context** — the field element voters derive their poll
pseudonym from — is not minted by anyone: it is
`context = H(envelope_hash(PollOpen))`. Deterministic (every replica gets the same one),
unpredictable before the poll exists (which is what stops a member pre-computing pseudonyms), and
unique per poll (which is what keeps votes in different polls unlinkable). It replaces the
server's `fresh_context()`.

A `Vote` carries a `Predicate` proof under `pseudonym_pred`: the voter proves
`claimed = Poseidon(sk, context)` and bulletin membership. Note what it **does not** prove: that
the voter is unbanned. `pseudonym_pred` checks membership and the pseudonym derivation and nothing
else — it never reads `banned` ([circuits.rs](../crates/personas-core/src/circuits.rs); contrast
the four *post* predicates, which do). In service mode that is the R4 finding; here it is the
**intended** behaviour, on your call — a banned member keeps a voice in moderating their own chat.
So this is a deliberate non-check, not an oversight, and it needs no circuit change. The replica
records the ballot against `claimed`. **One member, one vote** is dedupe on `claimed` — the rule
the server applies today ([polls.rs:463](../crates/personas-server/src/routes/polls.rs#L463)),
which tells you nothing about who voted. A later ballot from the same `claimed` **replaces** the
earlier one, matching `PollLog::cast`.

A poll **closes** at its close barrier, `close_epochs` after it opened (config, default 2) — not
when someone asks for a count. There is no one to ask. The tally is then a pure function of the
log, and `AllowedToRevoke` is finally what the paper wants it to be: the ban is a *consequence* of
the vote, not an admin's response to it — except when it *is* an admin's response, which §7's
`BanInvoke` now also allows.

Thread contexts (`ContextLog`) get the same treatment: a thread's context is the hash of the
record that opened it.

---

## 9. Joining, and the rate limit

`Join` is a bare object commitment and is accepted unconditionally — as today. Gating it needs
an invite, an invite is a Privacy Pass ticket, and tickets are service-only. So a serverless
group's Sybil resistance is exactly the messenger's: **whoever is in the Signal group can join
the protocol.** That is a smaller gap than it sounds — group membership is already the trust
boundary — but it means `banned` is only as durable as the difficulty of getting re-added to the
group, and the ban survives only because a rejoiner starts over with no standing. (`FINDINGS`
O7.)

A joiner cannot post until their object is in a root other replicas hold, which is the next append
they ingest — in practice immediately.

The **pseudonym cap** (`PostPseudoRate`) is worth restating because it is easy to misread.
`claimed = Poseidon(sk, context, i)` with `i ≠ MAX_PSEUDO` (4)
([circuits.rs:425](../crates/personas-core/src/circuits.rs#L425)) bounds the number of
*pseudonyms* a member may hold in one context to four — not the number of posts. Reusing an `i`
gives the same `claimed`, visibly the same pseudonym. Serverless changes none of this.

### How far a ban actually reaches (R4)

This is the redline's rate-limit worry, stated straight. Two mechanisms enforce a ban, and they
cover different things.

**The cryptographic gate** is the four post predicates checking `banned == 0`. But `banned` only
flips to 1 when the member **scans and absorbs** the ban callback, and the only thing that *forces*
a scan is the post budget `num_interactions_since_last_scan` reaching `NUM_INTS_BEFORE_SCAN` (200).
So between being banned and being forced to scan, a member can still make **up to 200 posts** whose
proofs show `banned == 0` because their object honestly still says so. Voting does not shrink this
window — a vote proves a predicate only and never advances the object (§8), so it neither ticks the
budget nor forces a scan. That is fine (a banned member is *allowed* to vote), but it means the
budget is the sole cryptographic forcing function, and 200 is a large loophole.

**The rendering gate** is what serverless adds, and it is why the loophole is smaller than it
looks. A ban is a public event (§7); every replica sees it. For a **pseudonymous** post the replica
can link — the post's `claimed` matches the banned pseudonym — so it can **flag or drop the post at
render time the instant it sees the ban**, without waiting for the member to scan. Enforcement is
immediate at the layer that matters (what people see), and the 200-post crypto window becomes
invisible for linkable activity.

For an **anonymous** post nothing links it to the banned member, so neither gate fires — and that
is not a bug, it is the definition of anonymity. You cannot suppress a banned member's future
*anonymous* posts without breaking every member's anonymity. A ban reaches exactly as far as the
banned activity is linkable: fully on a pseudonym, not at all on an anonymous post (§7, property 3).
Lowering `NUM_INTS_BEFORE_SCAN` tightens the crypto window if a deployment wants belt-and-braces;
the rendering gate is the real answer.

---

## 10. Ratings now need a proof

Today a rating carries no proof, because it needs none: the server knows which Slack/Signal
account reacted, and one account reacts once.

**Serverless erases exactly that.** Under the modified client every message arrives from the
shared phantom certificate (e2/D1), so a `Rate` record has no attributable sender — and an
unattributable, unproved rating can be sent a thousand times by one member. Reputation would be
worthless.

So a `Rate` record must carry a proof, and happily it needs **no new circuit**: reuse
`pseudonym_pred` with `context = H(target_envelope_hash)`. The rater proves membership and reveals
`claimed = Poseidon(sk, H(target))`. The replica accepts one rating per `claimed` per target. One
member, one rating, per message; unlinkable across messages; costs one Groth16 predicate proof the
client already knows how to make. The target is named by **envelope hash, not messenger id** —
messenger ids are sender-set and non-unique (§4), so a `MessageId` target would be ambiguous.

Because it is the same predicate as a vote, a rating is likewise **open to banned members** — a
banned member can still downvote. **This is a committed design choice** (decided 2026-07-14): for
the applications in view, a banned member keeping a rating voice is acceptable, and spite-
downvoting is tolerated rather than defended against. It is a choice and not a default — the
alternative (a `banned == 0` variant of `pseudonym_pred` plus a new key set) was considered and
declined. Recorded here and in `FINDINGS` D7 so a future reader who is surprised by it knows it was
deliberate. Revisit only if a deployment's threat model makes spite ratings load-bearing.

This is a genuine addition to the protocol, not a port — the clearest case of the serverless
design *costing* something rather than relocating it. ⚠ (It also quietly closes `FINDINGS` O4 —
"an emoji added by hand changes nobody's reputation" — by making the personas-layer rating the
only kind there is.)

---

## 11. Badges need an authority, and serverless has none

A badge asserts *"this person really is Faculty."* No tally over a chat log can establish that;
it is an attestation by someone trusted to know. Service mode has an admin. Serverless does not.

The options are: drop badges serverless; make them a group vote (which changes what a badge
*means* — "the group thinks you're Faculty"); or keep an explicit issuer. I propose the third,
because it is the only one that preserves the meaning: **a `BadgeGrant` is a record signed by a
key named in the group's config**, and the accept rule is "the signature verifies under a
configured authority key holding the `grant_badge` capability." No issuer configured → no badges,
and `BadgeRequest` records go unanswered.

This is the **same authority mechanism** as `BanInvoke` (§7), and deliberately so: a group's
config names a set of authority keys, each with a capability set drawn from `{ban, grant_badge}`.
The admin-ban mode you asked to restore is `ban`; the badge issuer is `grant_badge`; a deployment
can grant both to one key, split them, or configure neither. Modelling them as one thing keeps the
trusted surface legible — it is exactly this list and nothing else.

It reintroduces trusted parties, but *narrow* ones: an authority can ban a post or grant a badge
and can do **nothing else** — it cannot post, deanonymize, reorder, delay, or read anything a
member cannot. It need not be online (a `BanInvoke`/`BadgeGrant` is a record like any other, and
can be issued whenever). Naming this list is naming the entire residual trust in the group beyond
the messenger itself. ⚠

---

## 12. Late join, and the one new trust assumption

A member added to a Signal group **cannot read its history**. So a joiner cannot replay the log,
and therefore cannot compute the roots — which means they cannot make a proof anyone will accept,
or check a proof anyone makes.

`Snapshot` is the answer and it is the weakest part of this design. A `Snapshot` is a replica's
checkpoint: an epoch, the object and callback roots, the nullifier set, the called set, the open
tallies. A joiner adopts one and proceeds.

The honest account of what that costs:

- **It is not a soundness break.** A forged snapshot cannot make the joiner accept a forged
  proof — the proof still has to verify against the roots in the snapshot, and a root the rest of
  the group does not share makes the *joiner's own* proofs unacceptable to everyone else, loudly
  and immediately.
- **It is a view-integrity break.** A forged snapshot can show a banned member as unbanned, or
  omit a post. The joiner then sees a different chat from everyone else, and nothing tells them.

The redline killed my first mitigation. I proposed "accept a snapshot `q` members agree on," but
**join is ungated** (§9), so one member mints `q` Sybils for free and agrees with themselves — and
under the modified client (e2) every message comes from the shared phantom certificate, so a
replica **cannot even count distinct senders** to know whether `q` *people* agreed. Quorum-over-
senders is unbuildable here. The honest mitigation is trust-on-first-use over the human who added
you:

- **The inviter vouches.** Whoever added you to the Signal group is someone you already decided to
  trust enough to join. Accept their snapshot, pinned to the **genesis record hash carried
  out-of-band** with the invitation — the same shape as verifying a Signal safety number or an SSH
  host key on first connect. From then on you have the log and need no one's snapshot.
- **Divergence is detectable after the fact.** Once running, your roots either keep matching the
  records you ingest or they do not. A snapshot that lied shows up as *your* proofs being rejected
  by the group (§12 first bullet) — so a bad snapshot self-reveals within an epoch or two, it does
  not hide forever. A suspicious joiner can also ask a second member out-of-band for a snapshot and
  compare; equal roots is strong evidence, but it is a human check, not a protocol quorum.

**This is a trust assumption the as-a-service deployment does not have** (there, the joiner fetches
the bulletin from the one server and is done). It is the price of no server; it reduces to trusting
your inviter and pinning genesis, and it cannot be cryptographically removed without history the
messenger will not give us. Wants explicit sign-off. ⚠

---

## 13. Scanning

Unchanged in substance, and this is the demo path.

**`Scan` (Groth16) is the serverless default.** A scan over `k` outstanding callbacks is
`ceil(k/N)` records of a few KB each, inline. **`FoldScan` (Nova) is off by default**:
`RandomizedIVCProof` is megabyte-scale and dominated by witness field vectors, so `Compress::Yes`
does not rescue it — and serverless means *every member* downloads it, an n-fold amplification of
a cost the server used to pay once. The break-even that decides folding must include the
transport cost in serverless (c3), and with it, folding essentially never wins for realistic `k`.
It stays first-class in the replica engine and stays off.

The client's state machine tightens, though. Each interaction is built on the object the previous
one produced (§5.1), so the client tracks its own in-flight objects and **re-bases** any that get
orphaned by a reorg or lose a double-spend linearization (§5.4) — re-proving against the current
root rather than assuming its optimistic state stuck. Today's client has no such loop; it would
simply be wrong about its own state. (Related: `FINDINGS` O2 — `client scan` answers one callback
and panics if you interact mid-sweep. Serverless makes fixing that mandatory, not cosmetic.)

---

## 14. Parameters

| knob | default | what it trades |
|---|---|---|
| `heartbeat_secs` (E) | 60 | the settlement-barrier cadence, clocked by service-assigned `serverReceivedTimestamp` (§4). No longer the *ordering* mechanism (prefix-order is, §4). Shorter = tickets settle sooner and the outstanding set stays smaller, but barriers (hence scan-invalidation churn) come more often. **Implemented in d5** (`docs/D5_HEARTBEAT.md`): a record's barrier is `(received_at − genesis) / (heartbeat_secs·1000)`, bucketed by the *provider's* stamp — identical on every replica, so convergence is exact (§5.2's caveat closed). Shared with a `genesis` anchor (out of band, like the genesis pin). |
| `settlement_epochs` (W) | 48 hours of barriers | how many barriers a post's ticket lives. Longer = you can ban staler posts but the outstanding set and per-scan cost grow; shorter = ban polls must resolve fast. Interacts with `NUM_SCANS_PER_FOLD` — see below. ⚠ |
| `poll_close_epochs` | 24 hours of barriers | how many barriers a poll accepts votes for. |
| `object_root_window` (K) | 256 | how far behind a prover's object root may lag before a verifier drops rather than buffers it. Safe at any size (§5.1, monotone); bounded only by memory. |
| callback root | **latest barrier, not a knob** | a scan proves against the most recent barrier the verifier has reached (§5.2). No history, no window. This is the anti-monotone discipline; a "window" here re-opens O10. |
| `authority_keys` | **empty** | the config list of `(pubkey, capabilities ⊆ {ban, grant_badge})` (§7, §11). Empty = no admin ban and no badges — a fully leaderless group. Each key added is residual trust named explicitly. ⚠ |
| `NUM_SCANS_PER_FOLD` (N) | **1 today; needs c1** | at N=1, settling every ticket (§7) means ~one scan record per post — double the chat traffic. c1 (const-generic N) is therefore a **prerequisite of d**, not parallel. ⚠ |
| snapshot trust | **inviter TOFU** | a joiner trusts their inviter's snapshot against an out-of-band genesis pin (§12). Not a quorum — join is ungated and senders are uncountable under e2. ⚠ |
| `fold` | off | see §13. |
| tickets / Privacy Pass | **refused** | config hard-errors on `mode = serverless` with tickets enabled. |

---

## Sign-off checklist

The things I would not build on without a cryptographer's yes:

1. **§4 — prefix-ordering.** Ordering by the object root a record commits to, not by a
   sender-set timestamp, kills backdating (R1) and turns benign reorg (R2) into ordinary
   concurrency. Is the causal-order + envelope-hash-tiebreak linearization sound for the
   double-spend rule, and is "backdating is impossible, only withhold-and-release" right?
2. **§5.2 / §5.3 — the root discipline.** Object roots: any recent one, buffered if the prover is
   ahead (monotone, safe). Callback root: the latest *barrier* only, event-driven not wall-clock
   (anti-monotone, fatal otherwise). Plus the structural claim: switching to Merkle *forces* both
   roots into the public inputs (`is_*_data_const = false`), which fixes O10 for serverless more
   strongly than the in-circuit epoch equality we first proposed. Is the general law right?
3. **§5.4 — convergence.** Transient tip disagreement is fine; only a *persistent* fork on
   identical records is a bug. Re-basing orphaned in-flight objects, and rendering a
   later-discovered pre-ban post as *flagged* not deleted. Does this hold up?
4. **§6 — the ticket crypto provides no access control at all** (`pk == sk`, `Sig = ()`,
   `sk() == 0`), so serverless moderation rests entirely on the replica accept rule.
5. **§7 — triggers, not invocations.** Derived (heartbeat, poll) carry no record; authorized
   (`BanInvoke`, `BadgeGrant`) carry a signature. The settlement rule: one ticket, one call, ban
   precedes reputation, every ticket retired within `W`; the c1/N=1 cost; and "a ban reaches as
   far as the activity is linkable" (fully pseudonymous, never anonymous).
6. **§8 / §9 — banned members keep voting and rating** (decided): `pseudonym_pred` deliberately
   does *not* check `banned`, so no circuit change. Rating-while-banned / spite-downvoting is a
   **committed choice** (`FINDINGS` D7), not open. Still wants a review of the ban-reach analysis:
   crypto gate (≤200-post window) backstopped by the rendering gate (immediate for pseudonymous
   activity), and anonymous posts unbannable by construction.
7. **§10 — ratings must become proof-carrying**, reusing `pseudonym_pred` with
   `context = H(target_eh)`, keyed by envelope hash not messenger id.
8. **§11 / §7 — one authority mechanism** for admin-ban and badge-issue: a config list of keys
   with capabilities `⊆ {ban, grant_badge}`, narrow and offline-capable. Right shape? (Or drop
   badges and/or admin-ban entirely.)
9. **§12 — inviter TOFU** replaces the (Sybil-broken) snapshot quorum: trust your inviter's
   snapshot against an out-of-band genesis pin. A new trust assumption with no cryptographic
   removal, but a small and familiar one.
10. **O10 in *service* mode is still open.** This design routes around it; it does not fix the
    signature-store deployment, and the upstream circuit fix is still owed.
11. **§14 / d5 — bucketing barriers by the provider's `serverReceivedTimestamp`** (`FINDINGS`
    D9, accepted for now). The cadence clock is the *service-assigned* receive stamp, not the
    device clock (would fork honest replicas on delivery jitter) and not the sender-set message
    id (forgeable — a member could backdate). It adds no power the provider lacks under §4's
    delivery trust, and is used only for coarse cadence, never ordering or proof acceptance. The
    residual fork vector — a provider handing *different recipients different* stamps for one
    message — is the same class as selective delivery, already out of scope (§4). Right call, and
    is the "same class as censorship" dismissal fair?
