// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo, Phase 6 — the ACTION layer: the single place the app turns a UI
// gesture into a CryptoPersonas record on the wire.
//
// Phases 3-5 wired one gesture (compose a post) and left the rest of the record
// surface — rate, poll, vote, scan — reachable only from the engine addon. Everything
// here follows the same three steps, in this order, because the order is what keeps
// the guarantees:
//
//   1. `ensurePersonaJoined` — never emit a member record before membership exists.
//      A persona action that runs un-joined either throws (post) or is rejected by
//      every replica's accept rule (rate/vote), and in the composer's case used to
//      silently degrade into an attributable plain message.
//   2. emit + self-ingest through personasEngine (a member's own replica must contain
//      its own records, or its roots diverge from everyone else's).
//   3. route correctly, following what the CIRCUIT already does. POSTS, POLLS,
//      BALLOTS and RATINGS all identify their author by a pseudonym in-circuit, so all
//      four ride the shared phantom — an attributable envelope would re-identify what
//      the proof anonymised. So do SCANS, whose timing follows a member's private
//      tickets. JOINS stay attributable: the anti-Sybil accounting rests on one
//      membership per real account, which an anonymous join would defeat. See
//      personasCarriage for the marker split.
//
// Everything here is best-effort and logged: a failed action must never take down the
// message pipeline, and must never fall back to a weaker path.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { strictAssert } from '../util/assert.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  composePersonaPoll,
  composePersonaRate,
  commitPersonaScan,
  composePersonaVote,
  discardPersonaScan,
  personaScanStillValid,
  preparePersonaScan,
  isPersonasEngineEnabled,
  getPersonasEngine,
  groupIdOf,
  emitAndSelfIngest,
  type PersonaPollDescriptor,
} from './personasEngine.preload.ts';
import {
  BAN_POLL_OPTIONS,
  pollDescriptorFromRecord,
} from './personasCarriage.std.ts';
import { ensurePersonaJoined } from './personasMembership.preload.ts';
import { getBarrierSchedule } from './personasBarrier.preload.ts';
import { sleep } from '../util/sleep.std.ts';
import { isOutgoing } from '../messages/helpers.std.ts';
import { ToastType } from '../types/Toast.dom.tsx';

const log = createLogger('personasActions');

// Option 0 is the ban option, matching the engine's own e2e test
// (packages/personas-engine/test/converge.mjs) and the Rust replica test it mirrors.
// The engine decides settlement from the option INDEX, so the label order below is
// load-bearing: put "Keep" first and a majority to keep would revoke instead.
const BAN_OPTION_INDEX = 0;


strictAssert(
  BAN_POLL_OPTIONS[BAN_OPTION_INDEX] === 'Ban',
  'personasActions: the ban option must sit at BAN_OPTION_INDEX'
);

// Rate a persona post by delta (+1 / -1). `targetEh` is the post's envelope hash,
// persisted on the message as `personaEh`.
export async function sendPersonaRate(
  conversation: ConversationModel,
  targetEh: string,
  delta: number
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  try {
    if (!(await ensureReadyToProveIdentity(conversation))) {
      log.warn('sendPersonaRate: not joined; refusing to rate');
      return false;
    }
    const rate = composePersonaRate(groupIdOf(conversation), targetEh, delta);
    if (!rate) {
      return false;
    }
    await conversation.enqueueMessageForSend(
      { body: rate.body, attachments: [] },
      // Protocol traffic, not chatter: send it, but never show the raw carriage
      // string in our own timeline or conversation list. (It rides the phantom —
      // see encodeRateBody — so the rater's account is hidden on the wire too.)
      { hideFromTimeline: true }
    );
    log.info(
      `sendPersonaRate: rated ${targetEh.slice(0, 12)}… by ${delta} (eh ${rate.eh.slice(0, 12)}…)`
    );
    return true;
  } catch (error) {
    log.error(`sendPersonaRate failed: ${toLogFormat(error)}`);
    return false;
  }
}

// Open a poll. For a ban poll, `targetEh` names the post under review and option
// BAN_OPTION_INDEX is the ban. The message we enqueue keeps the poll's text so our own
// timeline draws the bubble immediately, exactly as recipients draw it from the record
// in the wire body (personaCarriageBody).
export async function sendPersonaPoll(
  conversation: ConversationModel,
  descriptor: PersonaPollDescriptor,
  targetEh?: string,
  // Send the poll RECORD without putting a poll bubble in the timeline.
  //
  // An admin's permanent ban still needs the poll record — that is the mechanism the
  // replica settles on — but showing the group a poll they are invited to vote in
  // misrepresents what happened: the decision is already made, and a visible poll
  // invites Keep votes that would cancel it. The record travels either way; only the
  // rendering is suppressed, exactly as ballots already are.
  { hidden = false }: { hidden?: boolean } = {}
): Promise<string | undefined> {
  if (!isPersonasEngineEnabled()) {
    return undefined;
  }
  try {
    if (!(await ensureReadyForUnprovenRecord(conversation))) {
      log.warn('sendPersonaPoll: not joined; refusing to open a poll');
      return undefined;
    }
    const poll = composePersonaPoll(groupIdOf(conversation), descriptor, targetEh);
    if (!poll) {
      return undefined;
    }
    await conversation.enqueueMessageForSend({
      // No plaintext of its own — the poll bubble renders from personaPoll.
      body: undefined,
      attachments: [],
      personaEh: poll.eh,
      // The poll rides the phantom, so its creator is unlinkable — including from
      // our own point of view. Label our copy Anonymous too, so the sender's screen
      // matches what every recipient sees.
      personaAnonymous: true,
      personaPoll: {
        ...pollDescriptorFromRecord(descriptor),
        target: descriptor.kind === 'ban' ? targetEh : undefined,
      },
      personaCarriageBody: poll.body,
    }, hidden ? { hideFromTimeline: true } : {});
    log.info(
      `sendPersonaPoll: opened ${descriptor.kind} poll (eh ${poll.eh.slice(0, 12)}…)`
    );
    // Return the poll's own eh, not just success. A caller that opens a poll usually
    // wants to act on it immediately — the ban flow casts the opener's ballot — and
    // without the eh there is no way to name the poll it just created.
    return poll.eh;
  } catch (error) {
    log.error(`sendPersonaPoll failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

// Open a ban poll on a specific post. The question names the persona rather than the
// account, because the persona is the only thing anyone is entitled to know.
/**
 * TWO CALLERS, distinguished by `decisive`:
 *
 *   `decisive: false` — "Request ban poll", available to EVERY member. Opens a poll and
 *     casts nothing: the group decides, and the ban lands only if Ban wins.
 *
 *   `decisive: true` — "Ban permanently", admins only. NOT a poll: a single Ban record
 *     (sendPersonaBan). See there.
 */
export async function sendPersonaBanPoll(
  conversation: ConversationModel,
  targetEh: string,
  persona: string | undefined,
  { decisive = false }: { decisive?: boolean } = {}
): Promise<boolean> {
  if (decisive) {
    return sendPersonaBan(conversation, targetEh);
  }
  const subject = persona ? `~${persona}` : 'this anonymous author';
  const pollEh = await sendPersonaPoll(
    conversation,
    {
      question: `Revoke ${subject}?`,
      options: [...BAN_POLL_OPTIONS],
      kind: 'ban',
    },
    targetEh
  );
  if (pollEh == null) {
    return false;
  }
  // A request, not a verdict: left unvoted on purpose.
  log.info('sendPersonaBanPoll: ban poll opened for the group to decide');
  return true;
}

/**
 * An admin's PERMANENT BAN of the author of post `targetEh`: one Ban record, no poll.
 *
 * At the next settlement barrier every replica invokes the post's callback with
 * BAN_FLAG, so the author's posts are flagged for everyone; the author's next scan
 * writes the ban into their object, and their posts stop being provable. Nobody can
 * vote it down.
 *
 * Sent under the admin's OWN account (the plain record marker, not the phantom), and
 * every member ingests it only from a Signal group admin (personasReset
 * `recordSenderProblem`). So the group can see which admin banned — the price of a ban
 * nobody can cancel; who wrote the post stays hidden.
 */
export async function sendPersonaBan(
  conversation: ConversationModel,
  targetEh: string
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  if (!conversation.areWeAdmin()) {
    log.warn('sendPersonaBan: only a group admin can ban');
    return false;
  }
  try {
    if (!(await ensureReadyForUnprovenRecord(conversation))) {
      log.warn('sendPersonaBan: not joined; refusing to ban');
      return false;
    }
    const result = emitAndSelfIngest(groupIdOf(conversation), engine =>
      engine.emitBan(targetEh)
    );
    if (!result) {
      return false;
    }
    await conversation.enqueueMessageForSend(
      { body: result.body, attachments: [] },
      { hideFromTimeline: true }
    );
    log.info(`sendPersonaBan: banned the author of ${targetEh.slice(0, 12)}…`);
    return true;
  } catch (error) {
    log.error(`sendPersonaBan failed: ${toLogFormat(error)}`);
    return false;
  }
}

// Cast a ballot. `pollEh` is the poll message's `personaEh`.
export async function sendPersonaVote(
  conversation: ConversationModel,
  pollEh: string,
  optionIndex: number
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  try {
    if (!(await ensureReadyToProveIdentity(conversation))) {
      log.warn('sendPersonaVote: not joined; refusing to vote');
      return false;
    }
    const vote = composePersonaVote(groupIdOf(conversation), pollEh, optionIndex);
    if (!vote) {
      return false;
    }
    await conversation.enqueueMessageForSend(
      { body: vote.body, attachments: [] },
      { hideFromTimeline: true }
    );
    log.info(
      `sendPersonaVote: voted option ${optionIndex} in ${pollEh.slice(0, 12)}… (eh ${vote.eh.slice(0, 12)}…)`
    );
    return true;
  } catch (error) {
    log.error(`sendPersonaVote failed: ${toLogFormat(error)}`);
    return false;
  }
}

// If `messageId` is a persona poll, cast the ballot through the engine and report
// true (the caller then skips Signal's own poll-vote send). A ZK ballot is
// single-choice, so only the first selected index is used.
//
// We also stash the chosen index on the message as `personaMyVote`. That is purely
// local bookkeeping for our own UI: a ballot is anonymous by construction, so the
// engine will never tell us — or anyone — which option was ours.
export async function maybeSendPersonaVote({
  messageId,
  optionIndexes,
}: {
  messageId: string;
  optionIndexes: ReadonlyArray<number>;
}): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }

  const message = window.MessageCache.getById(messageId);
  const pollEh = message?.get('personaEh');
  if (!message || !pollEh || message.get('personaPoll') == null) {
    return false;
  }

  const optionIndex = optionIndexes[0];
  if (optionIndex == null) {
    return false;
  }

  const conversation = window.ConversationController.get(
    message.get('conversationId')
  );
  if (!conversation) {
    return false;
  }

  const sent = await sendPersonaVote(conversation, pollEh, optionIndex);
  if (sent) {
    message.set({ personaMyVote: optionIndex });
    await window.MessageCache.saveMessage(message.attributes);
  }
  return true;
}

// ---------------------------------------------------------------------------
// Rating on Signal's own reaction gesture.
// ---------------------------------------------------------------------------

// The two emoji that mean "rate", and the delta each carries. Matched on the leading
// codepoint so every skin-tone variant (👍🏽, 👎🏿, …) counts the same — the rating is
// about the sentiment, not the modifier.
const THUMBS_UP = '\u{1F44D}';
const THUMBS_DOWN = '\u{1F44E}';

function rateDeltaForEmoji(emoji: string): number | undefined {
  if (emoji.startsWith(THUMBS_UP)) {
    return 1;
  }
  if (emoji.startsWith(THUMBS_DOWN)) {
    return -1;
  }
  return undefined;
}

// If this reaction is a thumbs on a persona post, emit it as a RATE record and report
// true (the caller then skips the ordinary Signal reaction). Anything else returns
// false and falls through untouched.
//
// A rating cannot be taken back: the replica counts one per member per post, so a second
// record would be dropped and the toast would claim something that never happened.
// `handled` means "this was a thumbs on a persona post, so do NOT fall through to an
// ordinary Signal reaction". `sent` reports whether the rate record actually went out.
//
// These have to be separate. Previously this returned a bare `true` as soon as it
// decided to handle the reaction, so a rating that FAILED still told the caller the
// gesture was dealt with: the ordinary reaction was skipped, no record was sent, and the
// user saw nothing whatsoever. Silent failure on a privacy-relevant action is the worst
// of the three outcomes, and it was the one that looked identical to success.
export type PersonaRateOutcome = {
  handled: boolean;
  sent: boolean;
  delta: number;
  /**
   * True when we blocked a non-thumbs reaction on a persona post because sending it
   * would have de-anonymised the reactor. The caller explains this rather than letting
   * the gesture fail mutely.
   */
  refusedEmoji?: boolean;
  /**
   * True when we declined to rate the user's OWN persona post. Distinct from a failure:
   * nothing went wrong, we chose not to (see the comment at the guard).
   */
  refusedSelf?: boolean;
};

export async function maybeSendPersonaRateForReaction({
  messageId,
  emoji,
  remove,
}: {
  messageId: string;
  emoji: string;
  remove: boolean;
}): Promise<PersonaRateOutcome> {
  const NOT_OURS: PersonaRateOutcome = {
    handled: false,
    sent: false,
    delta: 0,
  };
  if (!isPersonasEngineEnabled()) {
    return NOT_OURS;
  }

  const delta = rateDeltaForEmoji(emoji);

  const message = window.MessageCache.getById(messageId);
  const targetEh = message?.get('personaEh');
  if (!message || !targetEh || message.get('personaPoll') != null) {
    // Not a persona post (a poll is not rateable), so not ours to handle. A
    // non-thumbs reaction on an ORDINARY message is likewise none of our business.
    return NOT_OURS;
  }

  // On a persona post, a non-thumbs reaction is REFUSED rather than passed through.
  //
  // An ordinary Signal reaction is sent from the reactor's REAL account and addressed to
  // (target author, timestamp). On an anonymous or pseudonymous post that publicly ties
  // a named member to that specific post — it does not expose the author, but it does
  // expose the reactor, permanently and to everyone in the group. A heart is a much
  // weaker signal than a rating and carries a much higher disclosure cost, which is
  // precisely the trade nobody makes knowingly.
  //
  // Thumbs are safe because they are intercepted below and become rate records that
  // ride the phantom identity. Everything else is not, so it is declined with an
  // explanation rather than silently dropped.
  if (delta == null) {
    log.info(
      `maybeSendPersonaRateForReaction: refusing ${emoji} on a persona post (would send from the real account)`
    );
    return { handled: true, sent: false, delta: 0, refusedEmoji: true };
  }

  // SELF-RATING is refused, and this is a deliberate product decision rather than a
  // limitation we ran into.
  //
  // The protocol cannot catch it. `tally.rate` (personas-bulletin replica/tally.rs)
  // dedupes on `(target, claimed)` — one rating per pseudonym per target — but there is
  // no check that the rater is not the author, and there CANNOT usefully be one: the
  // author's pseudonym is H(sk, post_context) while the rater's is
  // H(sk, target.context()), so a replica sees two unrelated pseudonyms. That
  // unlinkability is the whole point of the scheme, and it means a member can inflate
  // their own reputation undetectably.
  //
  // So the client declines to offer it. That is ADVISORY — a modified client can still
  // do it, and the honest framing is that self-rating is an open soundness gap in the
  // serverless design, documented in the status panel's known limitations. Refusing it
  // here simply avoids shipping a button for it.
  if (isOutgoing(message.attributes)) {
    log.info(
      'maybeSendPersonaRateForReaction: refusing to rate our own persona post'
    );
    return { handled: true, sent: false, delta: 0, refusedSelf: true };
  }

  const conversation = window.ConversationController.get(
    message.get('conversationId')
  );
  if (!conversation) {
    return NOT_OURS;
  }

  if (remove) {
    log.info('maybeSendPersonaRateForReaction: a rating cannot be withdrawn');
    return { handled: true, sent: false, delta: 0 };
  }
  log.info(
    `maybeSendPersonaRateForReaction: routing ${emoji} to a rate of ${delta}`
  );
  const sent = await sendPersonaRate(conversation, targetEh, delta);
  return { handled: true, sent, delta };
}

// Emit a scan, absorbing the revocation callbacks fired since our last one. This is
// how a settled ban or a badge reaches the member's own object. It runs on the public
// schedule (personasScanSchedule) and never because the member is about to act.
// A scan is a SYNCHRONOUS Groth16 proof (`emitScan()` is a blocking napi call) executed
// in the render process, where the preload context lives. It is the most expensive thing
// this integration does: it holds the proving key set resident and blocks the main thread
// for its duration.
//
// The 30 s timer could never overlap with itself in practice, so this went unguarded.
// Then the "Scan now" menu item made overlap trivially reachable — a demo-nervous double
// click queues a second proof behind the first, and each one costs the full working set.
// Enough of them and the render process is SIGKILLed (exit code 9) rather than throwing
// anything catchable.
//
// So: one scan at a time, globally. A scan absorbs whatever is outstanding AT THE MOMENT
// IT RUNS, which means a request arriving while one is in flight would have been
// redundant anyway — dropping it loses nothing.
let scanInFlight = false;
let scanFinished: Promise<void> = Promise.resolve();

// SCAN TIMING. A scan pins the callback roots of the barrier it was proved in, and every
// replica rejects it if a settlement re-pinned them before the barrier its SERVICE
// timestamp falls in. So: start proving early in a barrier, check the scan is still valid
// right before releasing it, and never release it within SEND_MARGIN_MS of a boundary
// (that margin also absorbs clock skew between this machine and the server). A stale
// scan is discarded before it is sent — never undone after — so it reveals nothing
// (see Messenger::prepare_scan).
const SEND_MARGIN_MS = 2_500;
// And never start proving in the first moments of a barrier: a record stamped just before
// the boundary may still be in flight, and its arrival can change this barrier's
// settlement (a badge approval, say). The validity check before sending is the backstop.
const SETTLE_MS = 1_500;
const MAX_SCAN_ATTEMPTS = 3;
let lastScanProofMs = 4_000;

function msToNextBarrier(groupId: string): number | undefined {
  const schedule = getBarrierSchedule(groupId);
  if (!schedule) {
    return undefined;
  }
  const into = (Date.now() - schedule.anchorMs) % schedule.periodMs;
  return schedule.periodMs - into;
}

// If a barrier boundary is less than `needMs` away, wait until just past it and bring the
// replica onto the new barrier (settling whatever falls due there).
async function clearOfBarrier(
  groupId: string,
  needMs: number,
  settleMs = 0
): Promise<void> {
  const schedule = getBarrierSchedule(groupId);
  const left = msToNextBarrier(groupId);
  if (left == null || !schedule) {
    return;
  }
  const into = schedule.periodMs - left;
  if (left < needMs) {
    await sleep(left + settleMs + 300);
  } else if (into < settleMs) {
    await sleep(settleMs - into);
  } else {
    return;
  }
  getPersonasEngine(groupId)?.tick(Date.now());
}

// Prove, check and release one scan. Returns the record to send, or undefined if every
// attempt went stale. Throws "nothing to scan" when nothing is outstanding.
async function produceValidScan(
  groupId: string,
  dummy: boolean
): Promise<{ eh: string; body: string } | undefined> {
  for (let attempt = 1; attempt <= MAX_SCAN_ATTEMPTS; attempt += 1) {
    // oxlint-disable-next-line no-await-in-loop
    await clearOfBarrier(groupId, lastScanProofMs + SEND_MARGIN_MS, SETTLE_MS);
    const started = Date.now();
    if (preparePersonaScan(groupId, dummy) === undefined) {
      return undefined;
    }
    lastScanProofMs = Date.now() - started;
    try {
      // oxlint-disable-next-line no-await-in-loop
      await clearOfBarrier(groupId, SEND_MARGIN_MS);
    } catch (error) {
      // Never leave a prepared scan pending: it blocks every other persona action.
      // Discarding is safe — nothing has been released.
      discardPersonaScan(groupId);
      throw error;
    }
    if (personaScanStillValid(groupId)) {
      return commitPersonaScan(groupId);
    }
    discardPersonaScan(groupId);
    log.warn(`produceValidScan: attempt ${attempt} went stale at a settlement; discarded unsent`);
  }
  return undefined;
}


/**
 * Is this member banned in this group? `undefined` when it cannot be determined
 * (observer, or an addon without the binding) — deliberately tri-state, so callers can
 * avoid treating "don't know" as "not banned".
 */
export function isPersonaBanned(groupId: string | undefined): boolean | undefined {
  const engine = getPersonasEngine(groupId);
  if (!engine || typeof engine.isBanned !== 'function') {
    return undefined;
  }
  try {
    return engine.isBanned();
  } catch (error) {
    log.error(`isPersonaBanned: read failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Scan until the callback sweep is actually FINISHED, not just started.
 *
 * `sendPersonaScan` emits exactly one scan, and one scan does not necessarily complete a
 * sweep: the engine absorbs NUM_SCANS_PER_FOLD callbacks per scan and leaves
 * `scan_index` set while more remain. Every emit_* except `emit_scan` is refused while
 * that is true (`guard_not_scanning`).
 *
 * THIS IS THE BUG THIS FUNCTION EXISTS FOR. Approving a badge files a callback. The
 * requester's next message ran the one-shot send-time scan, which started the sweep and
 * left it unfinished, and the post that followed was refused — so the message failed to
 * send, with a generic error, specifically and only after an approval. Pressing "Scan
 * now" a few times fixed it by finishing the sweep by hand, which is exactly the clue:
 * one scan was not enough.
 *
 * Bounded, and the bound matters. An unbounded loop here would be a hang in the send
 * path if the engine ever reported scanning without making progress; a bound turns that
 * into a refused send with a reason, which is recoverable. Progress is also checked
 * directly — if a round does not shorten the sweep, stop rather than spin.
 */
/**
 * Run ONE complete sweep even if nothing has been invoked — what a reset request needs:
 * its "not banned" proof requires the object's last action to be a finished sweep.
 */
export async function runFullPersonaSweep(conversation: ConversationModel): Promise<boolean> {
  const engine = getPersonasEngine(groupIdOf(conversation));
  if (!engine) {
    return false;
  }
  if (engine.outstandingCallbacks() === 0) {
    return true; // nothing to sweep: the object is already in a swept state
  }
  for (let i = 0; i < 40; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    if (!(await sendPersonaScan(conversation, { quiet: true }))) {
      return false;
    }
    if (!engine.isScanning()) {
      return true;
    }
  }
  return false;
}

/**
 * Joined, and not in the middle of a sweep. The engine refuses every proving action while
 * a sweep is unfinished (a single "Scan now", or an interrupted drain, can leave one), so
 * ratings, votes, polls and badge actions finish it first instead of failing. Unlike a
 * post, they do not scan when nothing is under way — that stays the post's job.
 */
export async function ensureReadyForPersonaAction(
  conversation: ConversationModel
): Promise<boolean> {
  if (!(await ensurePersonaJoined(conversation))) {
    return false;
  }
  if (getPersonasEngine(groupIdOf(conversation))?.isScanning()) {
    return drainPersonaScans(conversation);
  }
  return waitUntilSettled(conversation);
}

// A vote or a rating needs a settled object, but not the newest, so it does not wait for
// the member's last action, and a sweep under way does not hold it up either.
async function ensureReadyToProveIdentity(
  conversation: ConversationModel
): Promise<boolean> {
  if (!(await ensureReadyForUnprovenRecord(conversation))) {
    return false;
  }
  const engine = getPersonasEngine(groupIdOf(conversation));
  return engine?.canProveIdentity() === true || waitUntilSettled(conversation);
}

// A poll, a ban or an approval carries no proof, so settling does not concern it. It only
// has to stay out of the way of a scan being released.
export async function ensureReadyForUnprovenRecord(
  conversation: ConversationModel
): Promise<boolean> {
  if (!(await ensurePersonaJoined(conversation))) {
    return false;
  }
  if (scanInFlight) {
    await scanFinished;
  }
  return true;
}

// A proof names a settled root, so a member's new object can be proved from only once its
// barrier has settled, a few seconds into the barrier after the action that made it.
const SETTLE_POLL_MS = 250;

async function waitUntilSettled(conversation: ConversationModel): Promise<boolean> {
  const groupId = groupIdOf(conversation);
  const engine = getPersonasEngine(groupId);
  if (!engine) {
    return false;
  }
  const periodMs = getBarrierSchedule(groupId)?.periodMs ?? 10_000;
  const deadline = Date.now() + 4 * periodMs;
  while (!engine.isSettled()) {
    if (Date.now() > deadline) {
      log.warn('waitUntilSettled: our last action has not settled');
      return false;
    }
    // oxlint-disable-next-line no-await-in-loop
    await sleep(SETTLE_POLL_MS);
  }
  return true;
}

export async function drainPersonaScans(
  conversation: ConversationModel,
  { maxRounds, onScan }: { maxRounds?: number; onScan?: () => void } = {}
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return true;
  }
  const engine = getPersonasEngine(groupIdOf(conversation));
  if (!engine || typeof engine.scanNeeded !== 'function') {
    // An older addon cannot tell us; fall back to the single speculative scan, which is
    // what the behaviour was before this existed.
    await sendPersonaScan(conversation, { quiet: true });
    return true;
  }

  // A sweep visits EVERY callback, one per scan, and `outstandingCallbacks` only drops
  // when the sweep ends — so progress is measured by `sweepRemaining`, never by the
  // outstanding count. (Measuring the count was the "no progress (3 -> 3)" refusal: any
  // member with more than one callback could not post until it pressed Scan now enough
  // times by hand, and that is also why badges seemed to need a manual scan.) The bound
  // allows a full sweep plus the one an absorbed callback can make necessary again.
  const limit = maxRounds ?? Math.min(2 * engine.outstandingCallbacks() + 2, 40);
  for (let round = 0; round < limit; round += 1) {
    // Nothing invoked, no sweep under way, not near the interaction cap: a scan would
    // prove that nothing happened. Skip it.
    if (!engine.scanNeeded()) {
      if (round > 0) {
        log.info(`drainPersonaScans: absorbed everything in ${round} scan(s)`);
      }
      return true;
    }
    const before = engine.isScanning()
      ? engine.sweepRemaining()
      : Number.POSITIVE_INFINITY;
    // eslint-disable-next-line no-await-in-loop
    const sent = await sendPersonaScan(conversation, { quiet: true });
    if (!sent) {
      log.error('drainPersonaScans: a scan could not be made; refusing the send');
      return false;
    }
    onScan?.();
    const after = engine.isScanning() ? engine.sweepRemaining() : 0;
    if (after >= before) {
      log.error(
        `drainPersonaScans: sweep made no progress (${before} -> ${after} left); refusing the send`
      );
      return false;
    }
  }

  log.error(`drainPersonaScans: still needed a scan after ${limit} rounds`);
  return false;
}

/**
 * A member's scans for one epoch: finish whatever real scanning is due, then send dummy
 * scans up to `count`, so every member sends the same number. See personasScanSchedule.
 */
export async function runScheduledScans(
  conversation: ConversationModel,
  count: number
): Promise<void> {
  const engine = getPersonasEngine(groupIdOf(conversation));
  if (!engine) {
    return;
  }
  let sent = 0;
  await drainPersonaScans(conversation, {
    onScan: () => {
      sent += 1;
    },
  });
  for (; sent < count; sent += 1) {
    // Never while a sweep runs, which a "Scan now" press can start at any moment.
    if (engine.isScanning()) {
      return;
    }
    // Each scan waits for the one before it to settle, which spaces them out.
    // oxlint-disable-next-line no-await-in-loop
    if (!(await sendPersonaScan(conversation, { quiet: true, dummy: true }))) {
      log.warn(`runScheduledScans: stopped after ${sent} of ${count} scans`);
      return;
    }
  }
}

export async function sendPersonaScan(
  conversation: ConversationModel,
  { quiet = false, dummy = false }: { quiet?: boolean; dummy?: boolean } = {}
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  // Each scan moves the object, so the one before it has to settle first. Not counted as
  // a scan in flight: nothing else needs to wait for this.
  if (!(await waitUntilSettled(conversation))) {
    return false;
  }
  if (scanInFlight) {
    // One scan at a time. Wait for the one under way (a "Scan now" press, say) and let
    // the caller re-check what is still needed, rather than fail the send.
    log.info('sendPersonaScan: a scan is already in flight; waiting for it');
    await scanFinished;
    return true;
  }
  // `quiet` is for a scan that may have nothing to do. The engine refuses a scan with
  // fewer than NUM_SCANS_PER_FOLD (=1) outstanding callbacks — `NothingToScan` — which
  // is not an error in any sense, and logging it as one would bury real failures.
  scanInFlight = true;
  let markFinished = (): void => undefined;
  scanFinished = new Promise<void>(resolve => {
    markFinished = resolve;
  });
  // Read BEFORE the scan: this is what makes the notification fire on the transition.
  const groupId = groupIdOf(conversation);
  const bannedBefore = isPersonaBanned(groupId);
  try {
    if (!groupId) {
      return false;
    }
    // A scan is only meaningful once we are a member, but unlike the others it should
    // not CAUSE a join — a lurking instance that never posted has nothing to absorb.
    const scan = await produceValidScan(groupId, dummy);
    if (!scan) {
      return false;
    }
    await conversation.enqueueMessageForSend(
      { body: scan.body, attachments: [] },
      { hideFromTimeline: true }
    );
    log.info(`sendPersonaScan: scan sent (eh ${scan.eh.slice(0, 12)}…)`);

    // THE BAN NOTIFICATION. A scan is the only thing that writes `banned` into the
    // member's object, so this is the first instant the client can know — and the ban
    // record itself is anonymous, so the member may never see it any other way.
    //
    // Compared against the value from BEFORE the scan so the toast fires once, on the
    // transition, rather than on every scan for the rest of the member's life.
    if (bannedBefore !== true && isPersonaBanned(groupId) === true) {
      log.warn('sendPersonaScan: this scan absorbed a BAN — notifying the member');
      window.reduxActions?.toast?.showToast({
        toastType: ToastType.PersonaBanned,
      });
    }
    return true;
  } catch (error) {
    const message = String(error);
    if (quiet && message.includes('nothing to scan')) {
      // Expected: no callbacks outstanding. Say nothing.
      return false;
    }
    log.error(`sendPersonaScan failed: ${toLogFormat(error)}`);
    return false;
  } finally {
    // `finally`, not a flag reset on each path: if this is ever left true the scan loop
    // stops silently and bans quietly never settle again — the worst failure mode this
    // integration has, because everything still LOOKS fine.
    scanInFlight = false;
    markFinished();
  }
}
