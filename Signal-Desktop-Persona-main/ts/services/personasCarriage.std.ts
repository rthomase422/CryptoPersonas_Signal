// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: the pure carriage convention — how a CryptoPersonas record is
// packed into an ordinary message body. No native/engine dependency, so the send
// path can import the marker without pulling in the addon.
//
// Mirrors personas-messenger carriage.rs `INLINE_MARKER`: a record body is
// `PZR2:<base64>`. A body without a marker is ordinary chatter.
//
// TEN markers. The split follows what the ENGINE already does: any record whose
// in-circuit identity is a pseudonym — or whose whole purpose is to prove something
// WITHOUT naming its author — must also hide its Signal sender, or the envelope
// re-identifies what the proof went to trouble to anonymise.
//   - POSTS (`PZP2:`) ride the shared phantom identity.
//   - POLLS (`PZQ2:`) ride the phantom, so the poll's CREATOR is anonymous. A recipient
//     draws the bubble from the record itself (`pollDescriptorFromRecord`).
//   - BALLOTS (`PZV2:`) ride the phantom. In-circuit the voter is
//     `H(sk, poll.context())` with no nonce — one pseudonym per poll, hence one vote
//     per member — so voting is PSEUDONYMOUS, not anonymous.
//   - RATINGS (`PZE2:`) ride the phantom for the same reason: `member.rate` uses
//     `context = target.context()`, giving one rating per member per target.
//   - BADGE REQUESTS / APPROVALS (`PZB2:`) ride the phantom. The grant travels by
//     CALLBACK, not by identity, so naming the sender leaked something the protocol
//     never used. See PERSONAS_BADGE_MARKER for what that costs an admin.
//   - AUTHORSHIP PROOFS (`PZU2:`) ride the phantom — a proof that two pseudonyms share
//     an author is worthless if the envelope says who sent it.
//   - BADGE PROOFS (`PZG2:`) ride the phantom, for the same reason: the point is that
//     SOMEONE holds the credential, not who.
//   - SCANS (`PZS2:`) ride the phantom: when and how often a member scans follows their
//     private tickets, so a named scan would identify their anonymous posts.
//   - JOINS (`PZR2:`) are sent ATTRIBUTABLY under the real account. They MUST be: the
//     anti-Sybil / ban-evasion guarantee depends on one membership per real account,
//     which an anonymous join would defeat.
//   - TOPIC ANNOUNCEMENTS (`PZT2:`) are not ZK records at all — coordination metadata
//     mapping a topic name to its random context. The engine never sees them.
// The record-bearing markers all yield the same CBOR bytes on decode (the engine
// classifies kind); the marker steers SEND-side routing and carries display metadata.

export const PERSONAS_MARKER = 'PZR2:';
export const PERSONAS_POST_MARKER = 'PZP2:';
export const PERSONAS_POLL_MARKER = 'PZQ2:';
export const PERSONAS_VOTE_MARKER = 'PZV2:';
// Ratings are pseudonymous in-circuit (member.rate uses context = target.context(),
// exactly like a vote), so they must ride the phantom too — otherwise the Signal
// envelope names the rater and the in-circuit pseudonym is pointless.
export const PERSONAS_RATE_MARKER = 'PZE2:';
// Scans ride the phantom: see isPersonaPhantomBody.
export const PERSONAS_SCAN_MARKER = 'PZS2:';
// Topic announcements are NOT ZK records — see decodeTopicAnnouncement.
export const PERSONAS_TOPIC_MARKER = 'PZT2:';

// An AUTHORSHIP PROOF: "these two pseudonyms are the same author".
//
// It carries a real Groth16 proof over `authorship_pred`, verified on receipt by
// `Engine::verify_authorship`, and a proof that fails is dropped rather than rendered.
// It is NOT a bulletin record, though, so it is decoded by its own path and never handed
// to `ingest` — which is why this marker is absent from ALL_MARKERS.
//
// PHANTOM-ROUTED. The proof establishes that two pseudonyms share an author while
// revealing nothing about who that is; sending it under the author's real account would
// answer that question in the envelope, for free, and make the proof pointless. It was
// attributable only for as long as it was an unverified typed claim, which it no longer
// is. (The names come from the proof's own public inputs, never from the body — see
// personasAuthorship.preload.ts.)
export const PERSONAS_AUTHORSHIP_MARKER = 'PZU2:';

// A BADGE REQUEST or APPROVAL. Its own marker, distinct from the attributable PZR2, for
// one reason: these ride the SHARED PHANTOM, so the requester and the approver are both
// unlinkable on the wire.
//
// That is a change of mind, and the reasoning matters. These started out attributable on
// the theory that "a request asks a human to vouch for you, which cannot be done
// anonymously". That turned out to be false about this protocol: the grant does not flow
// through identity at all. A request FILES A CALLBACK; the approval names that callback
// by its envelope hash; the replica marks the ticket and invokes it at the barrier; the
// requester absorbs it at their next scan because they alone hold the secret to do so.
// Identity appears nowhere in that chain, so attributing the Signal envelope was leaking
// something the protocol never needed.
//
// WHAT IT COSTS, stated plainly because it is a real trade: an admin now approves "a
// request for Faculty", not "Bob's request for Faculty". They cannot vouch for a person
// they recognise, because they cannot see who asked. If the research design needs
// person-specific vouching, this is the decision to revisit — not the UI label.
//
// `obj_root` in the record does NOT undo this. It is the root of the shared object tree,
// the same value for every member, which is why ordinary anonymous POSTS carry it too.
export const PERSONAS_BADGE_MARKER = 'PZB2:';

// A BADGE POSSESSION PROOF: "I hold a Faculty badge", proved in zero knowledge.
//
// Distinct from PZB2 (the request/approval records) and from the decorative `b` field
// inside a post envelope, and the three must not be confused:
//
//   PZB2:  a bulletin RECORD. Goes to `ingest`. Files or settles a callback.
//   PZG2:  a PROOF over `badge_pred`. Never ingested — verified and rendered.
//   post `b`: a STRING the sender chose. Checked against nothing. Decorative.
//
// Like authorship, this is a proof rather than a record, so it is absent from
// ALL_MARKERS and decoded by its own path. Phantom-routed for the same reason as
// authorship: the proof demonstrates that SOMEONE in the group holds the credential
// without saying who, and an attributable envelope would hand over the name for free.
export const PERSONAS_BADGE_PROOF_MARKER = 'PZG2:';

// Records that must ride the shared phantom identity, i.e. whose AUTHOR must be
// unlinkable. Everything else is attributable, and the ONLY thing that still has to be
// is the join: the anti-Sybil accounting rests on one membership per real account, which
// an anonymous join would defeat outright.
//
// AUTHORSHIP is in this list, which is the point of it. A proof that two pseudonyms share
// an author, sent under the author's real name, is self-defeating — the envelope answers
// the exact question the proof was built to leave unanswered. It was attributable only
// because it predated being a proof at all.
const PHANTOM_MARKERS = [
  PERSONAS_POST_MARKER,
  PERSONAS_POLL_MARKER,
  PERSONAS_VOTE_MARKER,
  PERSONAS_RATE_MARKER,
  PERSONAS_SCAN_MARKER,
  PERSONAS_BADGE_MARKER,
  PERSONAS_AUTHORSHIP_MARKER,
  PERSONAS_BADGE_PROOF_MARKER,
] as const;

// Markers whose payload is a ZK RECORD to hand to `ingest`. Authorship and topic
// announcements are deliberately absent: they are decoded by their own paths and must
// never reach the engine.
const ALL_MARKERS = [
  PERSONAS_MARKER,
  PERSONAS_POST_MARKER,
  PERSONAS_POLL_MARKER,
  PERSONAS_VOTE_MARKER,
  PERSONAS_RATE_MARKER,
  PERSONAS_SCAN_MARKER,
  PERSONAS_BADGE_MARKER,
] as const;

// How to attribute a composed post. Pure type (no engine dependency) so the
// composer UI can reference it without importing the native addon.
export type PersonaChoice =
  // An UNLIMITED plain pseudonym. Takes no topic: a member may mint as many of these
  // as they like, so each one carries a fresh random `nonce` to derive a new petname.
  | { kind: 'pseudo'; nonce: number }
  // One of the RATE-LIMITED personas, which ARE topic-scoped:
  //   persona = H(sk || context || index),  index < MAX_PSEUDO
  // `context` is the topic's random context number (see personasTopics), so the same
  // member has unlinkable petnames across topics, and at most MAX_PSEUDO identities
  // within any one topic.
  | { kind: 'rate'; context: number; index: number }
  // No linkable persona at all.
  | { kind: 'anon' };

// Rate-limited personas per context: three. MUST match
// `personas_core::circuits::RATE_LIMITED_PERSONAS_PER_CONTEXT` — every replica rejects a
// rate-limited post whose index is at or above it, so offering more slots would produce
// posts nobody accepts. Each context has its own three (persona = H(sk, context, index)).
//
// Since protocol version 3 the circuit itself proves the index is 0, 1 or 2 (`MAX_PSEUDO`
// = 3 there too), and the replica checks it again.
export const MAX_PSEUDO = 3;

// Wrap raw record bytes for carriage as a message body. Default marker is the
// ATTRIBUTABLE one (join / scan); posts, polls, ballots and ratings have their own.
export function encodeRecordBody(bytes: Buffer | Uint8Array): string {
  return PERSONAS_MARKER + Buffer.from(bytes).toString('base64');
}

/**
 * Wrap a BADGE REQUEST or APPROVAL record. Phantom-routed, so neither the requester nor
 * the approver is named on the wire.
 *
 * Same payload shape as `encodeRecordBody` — only the marker differs, because the marker
 * is what the send splice reads to decide routing. Using the attributable marker here is
 * what made these records name their sender.
 */
export function encodeBadgeBody(bytes: Buffer | Uint8Array): string {
  return PERSONAS_BADGE_MARKER + Buffer.from(bytes).toString('base64');
}

// Wrap a POST record — the one kind that rides the shared phantom identity.
//
// Two shapes behind the same marker, and the plain one is unchanged from before badges
// existed so old and new bodies interoperate:
//
//   PZP2:<base64 record>                     — no badge claim (the common case)
//   PZP2:<base64 {"r":"<record>","b":"..."}> — with a badge claim
//
// The badge is DISPLAY METADATA, exactly like a poll's option labels: untrusted, not
// part of the proof, and not checked by anything. See personasBadges.std.ts — a peer can
// claim any badge it likes. It is carried here rather than in the record because the
// record is the engine's and the engine has no notion of badges in the serverless model.
export function encodePostBody(
  bytes: Buffer | Uint8Array,
  badge?: string,
  contextName?: string
): string {
  const record = Buffer.from(bytes).toString('base64');
  if (!badge && !contextName) {
    return PERSONAS_POST_MARKER + record;
  }
  // `c` is the CONTEXT NAME, display metadata exactly like the badge and a poll's option
  // labels. The record already carries the context NUMBER in its public inputs, so the
  // number is authoritative and provable; the human-readable name is not, and a peer
  // could mislabel its own post's context. That is a display-integrity limit, not a
  // soundness one — the rate-limit still binds to the number inside the proof.
  //
  // Carried rather than resolved locally because a recipient may not have heard the
  // context announcement (PZT2) yet, and a post that renders with no context at all is
  // worse than one that renders with an unverified name.
  const envelope = { r: record, b: badge, c: contextName };
  return (
    PERSONAS_POST_MARKER +
    Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64')
  );
}

// The badge claim carried by a PZP2 body, if any. Undefined for a plain post, for a
// non-post, and for anything malformed — a badge is never worth failing a message over.
export function decodePostBadge(
  body: string | undefined | null
): string | undefined {
  if (!body?.startsWith(PERSONAS_POST_MARKER)) {
    return undefined;
  }
  const envelope = parsePostEnvelope(body);
  return typeof envelope?.b === 'string' ? envelope.b : undefined;
}

// The context NAME a post was made under, if it carried one. Undefined for an anonymous
// or context-free pseudonymous post. Untrusted — see encodePostBody.
export function decodePostContextName(
  body: string | undefined | null
): string | undefined {
  if (!body?.startsWith(PERSONAS_POST_MARKER)) {
    return undefined;
  }
  const envelope = parsePostEnvelope(body);
  return typeof envelope?.c === 'string' ? envelope.c : undefined;
}

// A post body is an envelope only if its base64 decodes to JSON with an `r` field.
// A plain post's payload is raw record bytes, which will not parse as JSON — so this
// distinguishes the two shapes without a second marker and without a version bump.
function parsePostEnvelope(
  body: string
): { r: string; b?: string; c?: string } | undefined {
  try {
    const json = Buffer.from(
      body.slice(PERSONAS_POST_MARKER.length),
      'base64'
    ).toString('utf8');
    const parsed = JSON.parse(json) as {
      r?: unknown;
      b?: unknown;
      c?: unknown;
    };
    if (typeof parsed?.r !== 'string') {
      return undefined;
    }
    return {
      r: parsed.r,
      b: typeof parsed.b === 'string' ? parsed.b : undefined,
      c: typeof parsed.c === 'string' ? parsed.c : undefined,
    };
  } catch {
    // Not JSON: a plain post. Expected, not exceptional.
    return undefined;
  }
}

// What to draw in a poll bubble. Built from the POLL RECORD (`pollDescriptorFromRecord`),
// never from anything else the sender supplies: nothing else binds to what the poll
// actually does, so a bubble drawn from separate text could say "Lunch at noon?" while
// the record is a ban poll whose first option is Ban.
export type PersonaPollDescriptor = {
  question: string;
  options: ReadonlyArray<string>;
  kind: 'ban' | 'standard';
};

// The labels of a ban poll, by option index. The replica counts option 0 as Ban and
// option 1 as Keep whatever the record's own labels say.
export const BAN_POLL_OPTIONS = ['Ban', 'Keep'] as const;
const BAN_POLL_QUESTION = "Ban this post's author?";

// A ban poll is always drawn with fixed wording, because its record's text is the
// opener's own and only the record's KIND decides what its options do.
export function pollDescriptorFromRecord(poll: {
  question: string;
  options: ReadonlyArray<string>;
  kind: string;
}): PersonaPollDescriptor {
  if (poll.kind === 'ban') {
    return {
      question: BAN_POLL_QUESTION,
      options: [...BAN_POLL_OPTIONS],
      kind: 'ban',
    };
  }
  return {
    question: poll.question,
    options: [...poll.options],
    kind: 'standard',
  };
}

// NOTE on poll_id. An earlier version of this carried a client-drawn random `pollId`,
// on the assumption the voter's pseudonym was PRF(sk, poll_id) for a server-issued
// poll_id. The engine does not work that way and never reads such a field:
//
//   member.vote()  ->  context = poll.context()  =  Poseidon(eh)
//                      claimed = pseudonym(sk, context) = H(sk, context)
//
// The poll's ENVELOPE HASH is the poll_id. record.rs says so explicitly — the context
// is "unpredictable until the record exists (which is what stops a member pre-computing
// a pseudonym), and unique per record", and it "replaces the service's fresh_context()".
// So the eh-derived context is the deliberate substitute for a server-drawn random id,
// and it has the same one-pseudonym-per-poll property because the derivation takes no
// nonce. Carrying an extra random number would be dead weight that nothing enforces.

// Wrap a POLL record. Its text is inside the record, so nothing rides beside it.
export function encodePollBody(bytes: Buffer | Uint8Array): string {
  return PERSONAS_POLL_MARKER + Buffer.from(bytes).toString('base64');
}

// The raw record bytes behind a body's marker (any of the three), or undefined for
// ordinary chatter. Kind (post vs join vs …) is the engine's job, not the marker's.
export function decodeRecordBody(
  body: string | undefined | null
): Buffer | undefined {
  if (!body) {
    return undefined;
  }
  const marker = ALL_MARKERS.find(m => body.startsWith(m));
  if (!marker) {
    return undefined;
  }
  try {
    if (marker === PERSONAS_POST_MARKER) {
      // A post is EITHER raw record bytes or a {r, b} envelope (see encodePostBody).
      // Unwrap when it is an envelope; otherwise fall through to the plain path. Getting
      // this wrong would hand the engine JSON instead of a record, so every badged post
      // would be rejected — which is why the envelope shape is detected by parse success
      // rather than assumed.
      const envelope = parsePostEnvelope(body);
      if (envelope) {
        return Buffer.from(envelope.r, 'base64');
      }
    }
    return Buffer.from(body.slice(marker.length), 'base64');
  } catch {
    return undefined;
  }
}

// Does this body carry a record whose AUTHOR must be unlinkable — i.e. one that MUST
// ride the shared phantom identity? Used by the group send splice to decide routing.
//
// Posts, polls, ballots, ratings, badge records and authorship proofs all qualify. A
// poll's creator and a voter are as entitled to anonymity as a poster: an attributable
// ballot would defeat the entire point of an anonymous poll, and an attributable poll
// would expose who called for a revocation.
//
// JOINS deliberately do not: the anti-Sybil and ban-evasion guarantees rest on one
// membership per real account. SCANS do: whether, when and how often a member scans
// depends on that member's private tickets, so a scan under a real name points at their
// anonymous posts, bans and badges. A scan creates no membership, so hiding its sender
// costs the join accounting nothing.
//
// (An earlier version of this comment claimed ratings were attributable. They are not,
// and never were in the code below — `member.rate` uses `context = target.context()`, so
// a rating is pseudonymous in-circuit and an attributable envelope would unmask it.)
export function isPersonaPhantomBody(body: string | undefined | null): boolean {
  if (!body) {
    return false;
  }
  return PHANTOM_MARKERS.some(m => body.startsWith(m));
}

// A topic announcement: `{name, context}` telling every member which context number to
// use for a named topic. NOT a ZK record — it carries no proof and the engine never
// sees it. It is pure coordination metadata, the stand-in for the personas server's
// topic registry, so it is decoded separately and never handed to `ingest`.
export type PersonaTopicAnnouncement = {
  name: string;
  context: number;
};

export function encodeTopicAnnouncement(
  announcement: PersonaTopicAnnouncement
): string {
  return (
    PERSONAS_TOPIC_MARKER +
    Buffer.from(JSON.stringify(announcement), 'utf8').toString('base64')
  );
}

// A PHANTOM BUNDLE: the shared phantom identity, certificate, trust root, the
// sender's CURRENT position on the shared chain, and the barrier schedule.
//
// Not a ZK record and never rendered. It is sent 1:1, over the pairwise Double Ratchet,
// by a member who holds the bundle to a fellow group member who does not — which is how
// a new member gets the material every other member already shares, without any shared
// folder or server. It is KEY MATERIAL (the phantom identity's private key and the
// chain's signing key), so it must only ever travel 1:1, never in a group body, and is
// dropped by the receiver before the message is saved.
//
// Sent ATTRIBUTABLY under the real account on purpose: the recipient decides whether to
// trust it by checking that the sender is a member of the group it names.
//
// Version 2: a bundle belongs to ONE Signal group (`groupId`). Each group has its own
// phantom identity, chain and barrier schedule, and so its own persona engine; a version
// 1 bundle named no group and was shared across all of them.
export const PERSONAS_PHANTOM_BUNDLE_MARKER = 'PZK1:';

export type PersonaPhantomBundleWire = {
  v: 2;
  // The Signal group (GroupV2 id) this bundle is for.
  groupId: string;
  trustRootPublic: string;
  phantomIdentityKeyPair: string;
  phantomCert: string;
  distributionId: string;
  skdm: string;
  // The sender's CURRENT full chain record, so the recipient starts where the group is.
  chainRecord: string;
  schedule: { anchorMs: number; periodMs: number };
};

export function encodePhantomBundle(bundle: PersonaPhantomBundleWire): string {
  return (
    PERSONAS_PHANTOM_BUNDLE_MARKER +
    Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64')
  );
}

export function decodePhantomBundle(
  body: string | undefined | null
): PersonaPhantomBundleWire | undefined {
  if (!body?.startsWith(PERSONAS_PHANTOM_BUNDLE_MARKER)) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(
      Buffer.from(
        body.slice(PERSONAS_PHANTOM_BUNDLE_MARKER.length),
        'base64'
      ).toString('utf8')
    ) as PersonaPhantomBundleWire;
    const strings = [
      parsed?.groupId,
      parsed?.trustRootPublic,
      parsed?.phantomIdentityKeyPair,
      parsed?.phantomCert,
      parsed?.distributionId,
      parsed?.skdm,
      parsed?.chainRecord,
    ];
    if (
      parsed?.v !== 2 ||
      !strings.every(field => typeof field === 'string' && field.length > 0) ||
      !Number.isFinite(parsed.schedule?.anchorMs) ||
      !(parsed.schedule?.periodMs > 0)
    ) {
      return undefined;
    }
    return parsed;
  } catch {
    return undefined;
  }
}

export function decodeTopicAnnouncement(
  body: string | undefined | null
): PersonaTopicAnnouncement | undefined {
  if (!body?.startsWith(PERSONAS_TOPIC_MARKER)) {
    return undefined;
  }
  try {
    const json = Buffer.from(
      body.slice(PERSONAS_TOPIC_MARKER.length),
      'base64'
    ).toString('utf8');
    const parsed = JSON.parse(json) as PersonaTopicAnnouncement;
    if (typeof parsed?.name !== 'string' || !Number.isFinite(parsed?.context)) {
      return undefined;
    }
    return { name: parsed.name, context: parsed.context };
  } catch {
    return undefined;
  }
}

// Wrap a VOTE record. Separate from the generic marker because a ballot rides the
// phantom (see isPersonaPhantomBody) while joins/ratings/scans do not.
// An authorship claim: "these two personas are both me". UNVERIFIED — see the marker
// comment. Sent ATTRIBUTABLY on purpose: the claimant is voluntarily linking two of
// their own personas, so there is nothing left to hide about who is speaking, and
// routing it over the phantom would falsely suggest the link itself is protected.
export type PersonaAuthorshipClaim = {
  /** The two persona petnames being linked. */
  first: string;
  second: string;
};

/**
 * Wrap a ZK authorship PROOF for the wire.
 *
 * Deliberately carries ONLY the proof. The previous version shipped the two petnames
 * as plain strings, which is what made the claim unverifiable: a recipient had nothing
 * to check and could only repeat what the sender asserted.
 *
 * Names are NOT carried, on purpose. They are recoverable from the proof's own public
 * inputs (`Engine.verifyAuthorship` returns them), and carrying them would create a
 * second, untrusted source for the same fact — which is exactly how a true checkmark
 * ends up next to a false statement. If a name is not in the message, it cannot be
 * believed by mistake.
 */
export function encodeAuthorshipProof(proof: Uint8Array): string {
  return (
    PERSONAS_AUTHORSHIP_MARKER + Buffer.from(proof).toString('base64')
  );
}

/**
 * Wrap a BADGE POSSESSION proof for carriage.
 *
 * Carries ONLY the proof — no badge name. The name is an output of verification, which
 * is the same rule authorship follows and for the same reason: if the name travelled
 * alongside, a sender holding a valid Industry proof could render it as Faculty and the
 * verified checkmark would be true while the statement was false.
 */
export function encodeBadgeProof(proof: Uint8Array): string {
  return (
    PERSONAS_BADGE_PROOF_MARKER + Buffer.from(proof).toString('base64')
  );
}

/** The raw proof bytes behind a badge-proof message, for the engine to verify. */
export function decodeBadgeProof(
  body: string | undefined | null
): Buffer | undefined {
  if (!body?.startsWith(PERSONAS_BADGE_PROOF_MARKER)) {
    return undefined;
  }
  try {
    return Buffer.from(
      body.slice(PERSONAS_BADGE_PROOF_MARKER.length),
      'base64'
    );
  } catch {
    return undefined;
  }
}

/** The raw proof bytes behind an authorship message, for the engine to verify. */
export function decodeAuthorshipProof(
  body: string | undefined | null
): Buffer | undefined {
  if (!body?.startsWith(PERSONAS_AUTHORSHIP_MARKER)) {
    return undefined;
  }
  try {
    return Buffer.from(
      body.slice(PERSONAS_AUTHORSHIP_MARKER.length),
      'base64'
    );
  } catch {
    return undefined;
  }
}

export function decodeAuthorshipClaim(
  body: string | undefined | null
): PersonaAuthorshipClaim | undefined {
  if (!body?.startsWith(PERSONAS_AUTHORSHIP_MARKER)) {
    return undefined;
  }
  try {
    const json = Buffer.from(
      body.slice(PERSONAS_AUTHORSHIP_MARKER.length),
      'base64'
    ).toString('utf8');
    const parsed = JSON.parse(json) as { a?: unknown; b?: unknown };
    if (typeof parsed?.a !== 'string' || typeof parsed?.b !== 'string') {
      return undefined;
    }
    return { first: parsed.a, second: parsed.b };
  } catch {
    return undefined;
  }
}

export function encodeVoteBody(bytes: Buffer | Uint8Array): string {
  return PERSONAS_VOTE_MARKER + Buffer.from(bytes).toString('base64');
}

// Wrap a RATE record. Like a ballot, it rides the phantom.
export function encodeScanBody(bytes: Buffer | Uint8Array): string {
  return PERSONAS_SCAN_MARKER + Buffer.from(bytes).toString('base64');
}

export function encodeRateBody(bytes: Buffer | Uint8Array): string {
  return PERSONAS_RATE_MARKER + Buffer.from(bytes).toString('base64');
}

// A RESET REQUEST: a member asks the group's admins to let its account join once more
// (personasReset). NOT a ZK record, and deliberately ATTRIBUTABLE — it rides the member's
// real account, never the phantom: an admin is being asked to vouch for a person, and
// the one-join-per-account rule only means something if the request names the account.
//
//   PZX1:<base64 {"a": "<ACI hex>", "p": "<not-banned proof base64>" | null, "r"?: reason}>
//
// `p` is the "not banned and just swept" proof (Engine.proveNotBanned); null when the
// member could not make one (out of sync, or banned), with `r` saying why, so the admin
// decides knowing that.
export const PERSONAS_RESET_REQUEST_MARKER = 'PZX1:';

export type PersonaResetRequestWire = {
  a: string;
  p: string | null;
  r?: string;
};

export function encodeResetRequest(request: PersonaResetRequestWire): string {
  return (
    PERSONAS_RESET_REQUEST_MARKER +
    Buffer.from(JSON.stringify(request), 'utf8').toString('base64')
  );
}

export function decodeResetRequest(
  body: string | undefined | null
): PersonaResetRequestWire | undefined {
  if (!body?.startsWith(PERSONAS_RESET_REQUEST_MARKER)) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(
      Buffer.from(body.slice(PERSONAS_RESET_REQUEST_MARKER.length), 'base64').toString(
        'utf8'
      )
    ) as Partial<PersonaResetRequestWire>;
    if (
      typeof parsed.a !== 'string' ||
      !/^[0-9a-f]{32}$/.test(parsed.a) ||
      (parsed.p != null && typeof parsed.p !== 'string') ||
      (parsed.r !== undefined && typeof parsed.r !== 'string')
    ) {
      return undefined;
    }
    return { a: parsed.a, p: parsed.p ?? null, ...(parsed.r ? { r: parsed.r.slice(0, 200) } : {}) };
  } catch {
    return undefined;
  }
}

// A RELAYED RECORD (SERVERLESS_PROTOCOL.md §5.5). Every record carries a hash of its
// sender's view of the group; when a received one disagrees with ours, Signal may have
// withheld records from some members, so we re-send the records we hold from around
// that point:
//
//   PZY2:<barrier>:<base64 record>
//
// `barrier` is where we placed the record. The receiver places it there, but never later
// than the relay message itself. Same format as the Rust carriage (carriage.rs).
//
// Sent ATTRIBUTABLY under the real account, like a scan: a relay claims nothing about
// who wrote the record (every member holds every record), so it reveals nothing. Joins,
// re-join approvals and admin bans are never relayed: they are accepted only because of
// who sent them, which a relay would hide. Not in ALL_MARKERS, so `decodeRecordBody`
// never returns a relayed record and the sender checks never see one.
export const PERSONAS_RELAY_MARKER = 'PZY2:';

export function encodeRelayBody(barrier: number, record: Uint8Array): string {
  return `${PERSONAS_RELAY_MARKER}${barrier}:${Buffer.from(record).toString('base64')}`;
}

export function decodeRelayBody(
  body: string | undefined | null
): { barrier: number; record: Buffer } | undefined {
  if (!body?.startsWith(PERSONAS_RELAY_MARKER)) {
    return undefined;
  }
  const rest = body.slice(PERSONAS_RELAY_MARKER.length);
  const colon = rest.indexOf(':');
  const barrier = Number(rest.slice(0, colon));
  if (colon < 0 || !Number.isSafeInteger(barrier) || barrier < 0) {
    return undefined;
  }
  const record = Buffer.from(rest.slice(colon + 1), 'base64');
  return record.length > 0 ? { barrier, record } : undefined;
}

// LATE-JOIN CATCH-UP (personasCatchUp). A member added after the group started posting
// has none of the group's records, so its posts name a tree nobody else has and it
// cannot apply anyone else's. It asks; a group admin sends its history.
//
//   PZC1:<base64 {"v": 1}>      the REQUEST, to the group, under the member's own account
//   PZH1:<base64 {"g": groupId, "s": copy id, "i": part, "n": parts, "d": data}>
//                               one PART of the history, 1:1 from an admin, under the
//                               admin's own account; `d` is a base64 slice of
//                               Engine.exportCatchUp (no message text in it)
//
// Parts keep each body under Signal's 2 KiB inline limit: a longer body would travel
// as a long-text attachment and arrive here truncated.
export const PERSONAS_CATCH_UP_REQUEST_MARKER = 'PZC1:';

// Any personas carriage at all (every marker is `PZ`, a letter, a digit, a colon). Used
// to drop personas traffic in a group that is not this app's personas group.
export function isPersonasCarriage(body: string | undefined | null): boolean {
  return body != null && /^PZ[A-Z][0-9]:/.test(body);
}
export const PERSONAS_CATCH_UP_PART_MARKER = 'PZH1:';
export const CATCH_UP_PART_DATA_CHARS = 1400;

export type PersonaCatchUpPartWire = {
  g: string;
  s: string;
  i: number;
  n: number;
  d: string;
};

export function encodeCatchUpRequest(): string {
  return (
    PERSONAS_CATCH_UP_REQUEST_MARKER +
    Buffer.from(JSON.stringify({ v: 1 }), 'utf8').toString('base64')
  );
}

export function isCatchUpRequest(body: string | undefined | null): boolean {
  return body?.startsWith(PERSONAS_CATCH_UP_REQUEST_MARKER) === true;
}

/** Split an exported history into the parts that carry it. */
export function encodeCatchUpParts(
  groupId: string,
  copyId: string,
  history: Uint8Array<ArrayBuffer>
): Array<string> {
  const data = Buffer.from(history).toString('base64');
  const n = Math.max(1, Math.ceil(data.length / CATCH_UP_PART_DATA_CHARS));
  const parts: Array<string> = [];
  for (let i = 0; i < n; i += 1) {
    const wire: PersonaCatchUpPartWire = {
      g: groupId,
      s: copyId,
      i,
      n,
      d: data.slice(i * CATCH_UP_PART_DATA_CHARS, (i + 1) * CATCH_UP_PART_DATA_CHARS),
    };
    parts.push(
      PERSONAS_CATCH_UP_PART_MARKER +
        Buffer.from(JSON.stringify(wire), 'utf8').toString('base64')
    );
  }
  return parts;
}

export function decodeCatchUpPart(
  body: string | undefined | null
): PersonaCatchUpPartWire | undefined {
  if (!body?.startsWith(PERSONAS_CATCH_UP_PART_MARKER)) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(
      Buffer.from(body.slice(PERSONAS_CATCH_UP_PART_MARKER.length), 'base64').toString(
        'utf8'
      )
    ) as Partial<PersonaCatchUpPartWire>;
    const { g, s, d, i, n } = parsed;
    if (
      typeof g !== 'string' ||
      typeof s !== 'string' ||
      typeof d !== 'string' ||
      typeof i !== 'number' ||
      typeof n !== 'number' ||
      !Number.isInteger(i) ||
      !Number.isInteger(n) ||
      n < 1 ||
      n > 10_000 ||
      i < 0 ||
      i >= n
    ) {
      return undefined;
    }
    return { g, s, i, n, d };
  } catch {
    return undefined;
  }
}
