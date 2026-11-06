// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: the bridge between Signal-Desktop and the CryptoPersonas ZK engine
// (`@signalapp/personas-engine`, a napi addon over the transport-agnostic
// Replica + Member). Desktop is the transport: `emit*` produce record bytes with
// real Groth16 proofs that we carry as an ordinary message body, and every incoming
// body is checked for a record to `ingest`. No Signal crypto lives here.
//
// This is the Phase 3 "attributable bring-up": records ride over Desktop's real
// send/receive path, the sender still its own real account. Recipient-anonymity
// (the shared phantom identity) is Phase 5.
//
// Gated on PERSONAS_AUTO_REGISTER / PERSONAS_KEYS_DIR so normal builds are inert.

import { homedir } from 'node:os';
import { join } from 'node:path';

import { Engine } from '@signalapp/personas-engine';
import type {
  IngestStatus,
  Emitted,
  ViewReport,
} from '@signalapp/personas-engine';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { badgeSlotFromLogBody } from './personasBadgeRules.std.ts';
import { setOwnRecordSettler, stampOwnRecord } from './personasRegistry.std.ts';
import {
  encodeRecordBody,
  encodeBadgeBody,
  encodePollBody,
  encodeVoteBody,
  encodeRateBody,
  encodeScanBody,
  decodeRecordBody,
  pollDescriptorFromRecord,
  decodeRelayBody,
  encodeRelayBody,
  type PersonaChoice,
  type PersonaPollDescriptor,
  encodeAuthorshipProof,
  encodeBadgeProof,
} from './personasCarriage.std.ts';
import {
  getPhantomBundleFingerprint,
  hasPhantomMaterial,
  setPhantomJoinCheck,
} from './personasPhantom.preload.ts';
import {
  initPersonasPersistence,
  loadPersonasState,
  openPersonasGroupState,
  savePersonasState,
} from './personasPersistence.preload.ts';
import { initPersonasCatchUp } from './personasCatchUp.preload.ts';
import {
  benchLog,
  benchNowMs,
  benchProofKey,
  isBenchLogEnabled,
} from './personasBenchLog.node.ts';
import {
  ensureProvingKeys,
  getPinnedKeysSha256,
} from './personasKeys.preload.ts';
import { drop } from '../util/drop.std.ts';
import { ToastType } from '../types/Toast.dom.tsx';
import { sleep } from '../util/sleep.std.ts';
import {
  getBarrierSchedule,
  ingestTimestampFor,
  startBarrierTicker,
} from './personasBarrier.preload.ts';

export {
  PERSONAS_MARKER,
  encodeRecordBody,
  decodeRecordBody,
} from './personasCarriage.std.ts';
export type {
  PersonaChoice,
  PersonaPollDescriptor,
} from './personasCarriage.std.ts';

const log = createLogger('personasEngine');

// OFF unless PERSONAS_VIEW_CHECKS=1 at launch: a view claim reveals which records its
// sender had seen, so a member who sends a record to one victim only can recognise the
// victim's next records until a relay heals the split (SERVERLESS_PROTOCOL.md §5.5,
// "Tagging"). With it off, records carry no claim and relays are ignored.
const VIEW_CHECKS = process.env.PERSONAS_VIEW_CHECKS === '1';

// One shared conversation label for the demo group (the engine is single-conversation;
// the id is just a tag). All members must use the same value.
const PERSONAS_CONVERSATION = 'personas-demo';

const DEFAULT_KEYS_DIR = join(homedir(), '.personas-demo-keys');

export function isPersonasEngineEnabled(): boolean {
  return Boolean(
    process.env.PERSONAS_AUTO_REGISTER || process.env.PERSONAS_KEYS_DIR
  );
}

function getKeysDir(): string {
  return process.env.PERSONAS_KEYS_DIR?.trim() || DEFAULT_KEYS_DIR;
}

// ONE ENGINE PER PERSONAS GROUP. Each group has its own phantom bundle, barrier schedule,
// member object, replica and saved state; nothing is shared between them. Every function
// below takes the Signal group id (GroupV2 id) it acts in.
type GroupRuntime = {
  engine?: Engine;
  constructionFailed: boolean;
  readyWaiters: Array<() => void>;
};
const runtimes = new Map<string, GroupRuntime>();

// For bundle distribution: has `serviceId`'s join reached this group's engine? A member
// that never joined is sent the group's bundle again (personasPhantom).
setPhantomJoinCheck((groupId, serviceId) => {
  const engine = runtimes.get(groupId)?.engine;
  if (!engine) {
    return undefined;
  }
  try {
    return engine.joinCounts(serviceId.replaceAll('-', '').toLowerCase()).joins > 0;
  } catch {
    return undefined;
  }
});

function runtimeFor(groupId: string): GroupRuntime {
  let runtime = runtimes.get(groupId);
  if (!runtime) {
    runtime = { constructionFailed: false, readyWaiters: [] };
    runtimes.set(groupId, runtime);
  }
  return runtime;
}

// The group id of a conversation (undefined for a 1:1 chat).
export function groupIdOf(
  conversation: { get(key: 'groupId'): string | undefined } | undefined
): string | undefined {
  return conversation?.get('groupId') ?? undefined;
}

// --- experiment log (personasBenchLog; inert unless PERSONAS_BENCH_LOG is set) ---------

// A short, stable tag per group, so a log never carries the group id itself.
const groupTag = (groupId: string): string =>
  benchProofKey(Buffer.from(groupId, 'utf8')).slice(0, 8);

// The engine's record kind ("BadgeRequest") as the log names operations ("badge_request").
const opName = (engine: Engine, eh: string, fallback: string): string =>
  (engine.logEntry(eh)?.kind ?? fallback)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .toLowerCase();

function benchEmitted(
  groupId: string,
  engine: Engine,
  op: string,
  startMs: number,
  key: string
): void {
  if (!isBenchLogEnabled()) {
    return;
  }
  const t =
    typeof engine.lastOpTimings === 'function'
      ? engine.lastOpTimings()
      : undefined;
  benchLog({
    event: 'emit',
    op,
    group: groupTag(groupId),
    key,
    startMs,
    endMs: benchNowMs(),
    proveMs: t?.proveMs,
    selfIngestMs: t?.selfIngestMs,
    bytes: t?.bytes,
  });
}

const lastSettleLogged = new Map<string, number>();
function benchSettled(groupId: string, engine: Engine): void {
  if (!isBenchLogEnabled() || typeof engine.lastSettleTimings !== 'function') {
    return;
  }
  const t = engine.lastSettleTimings();
  if (!t || lastSettleLogged.get(groupId) === t.barrier) {
    return;
  }
  lastSettleLogged.set(groupId, t.barrier);
  benchLog({ event: 'settle', group: groupTag(groupId), ...t });
}

// With a pinned key hash, an engine is built only once the downloaded keys verified.
let keysReady = false;
let keysRetry: NodeJS.Timeout | undefined;
// The state key must be fetched (async) before an engine is built, so a saved member
// can be restored rather than replaced by a new one.
let persistenceReady = false;

// For the receive path: a record that arrives while its group's engine is still starting
// (the queue drained right after launch, i.e. everything sent while this member was
// offline) must WAIT for it. Dropping it would leave the replica without that record, and
// every later post builds on it — the member would fork off the group. Returns at once
// when the engine exists or is not coming (disabled, failed, or no bundle for the group).
export async function waitForPersonasEngineIfStarting(
  groupId: string | undefined,
  timeoutMs = 120_000
): Promise<void> {
  if (!groupId || !isPersonasEngineEnabled() || !hasPhantomMaterial(groupId)) {
    return;
  }
  const runtime = runtimeFor(groupId);
  if (runtime.engine || runtime.constructionFailed) {
    return;
  }
  await Promise.race([
    sleep(timeoutMs),
    new Promise<void>(resolve => {
      runtime.readyWaiters.push(resolve);
    }),
  ]);
}
const KEYS_RETRY_MS = 30_000;

// A group's engine (one Member per group per process). Built lazily on first use;
// construction reads the ~51MB key bundle and mints this member's keypair for the group.
// Returns undefined if disabled, if the group has no bundle, or if construction failed
// (so callers never crash the message pipeline).
export function getPersonasEngine(
  groupId: string | undefined
): Engine | undefined {
  if (!groupId || !isPersonasEngineEnabled()) {
    return undefined;
  }
  const runtime = runtimeFor(groupId);
  if (runtime.engine || runtime.constructionFailed) {
    return runtime.engine;
  }
  // Wait for the group's phantom bundle: it carries the barrier schedule every member
  // must share, and the replica's schedule is fixed at construction. Background warms
  // the engine again the moment the bundle is minted or adopted.
  if (!hasPhantomMaterial(groupId)) {
    return undefined;
  }
  // And for the proving keys when they come from our server (personasKeys): built
  // before they arrive, the engine would generate a private, incompatible set.
  if (getPinnedKeysSha256() && !keysReady) {
    return undefined;
  }
  if (!persistenceReady) {
    return undefined;
  }
  const dataDir = getKeysDir();
  // The group's SHARED barrier schedule: every member buckets an ingest by the record's
  // timestamp rather than local arrival order, so replicas stay converged AND settlement
  // barriers actually pass — which is what lets a ban poll close and a ban bite.
  const schedule = getBarrierSchedule(groupId);
  // Continue as the saved member, on the saved replica (personasPersistence). Without a
  // state key both are undefined and the engine starts fresh, in memory.
  const fingerprint = getPhantomBundleFingerprint(groupId);
  // Keyed by protocol version too: a version-3 replica cannot read version-2 records,
  // and a member saved under version 2 joined without a proof, so both start fresh.
  const groupState = fingerprint
    ? openPersonasGroupState(groupId, `${fingerprint}-v3`)
    : undefined;
  const memberState = groupState ? loadPersonasState(groupId) : undefined;
  const wakeAll = () => {
    for (const wake of runtime.readyWaiters.splice(0)) {
      wake();
    }
  };
  try {
    const engine = new Engine({
      dataDir,
      conversation: PERSONAS_CONVERSATION,
      ...(schedule
        ? {
            heartbeatAnchorMs: schedule.anchorMs,
            heartbeatPeriodMs: schedule.periodMs,
          }
        : {}),
      ...(memberState ? { memberState } : {}),
      ...(groupState ? { journalPath: groupState.journalPath } : {}),
      viewChecks: VIEW_CHECKS,
    });
    runtime.engine = engine;
    if (memberState) {
      log.info(
        `restored the saved member (${
          engine.memberOnBulletin()
            ? 'on the bulletin'
            : 'NOT on the restored bulletin'
        })`
      );
    } else {
      // A new member: save it now, before its join can be sent.
      const state = engine.exportMemberState();
      savePersonasState(groupId, state ? Buffer.from(state) : undefined);
    }
    // A new member has an empty replica: it needs the group's history first.
    initPersonasCatchUp(groupId, { fresh: !memberState });
    log.info(
      `constructed an engine (keys: ${dataDir}; ${
        schedule
          ? `shared barrier schedule anchor=${schedule.anchorMs} period=${schedule.periodMs}ms`
          : 'local-barrier cadence'
      })`
    );
    // Advance the replica along the schedule so settlement happens on time even in a
    // silent group. No-op when there is no shared schedule.
    startBarrierTicker(groupId, nowMs => {
      const barrier = runtime.engine?.tick(nowMs);
      if (runtime.engine) {
        benchSettled(groupId, runtime.engine);
        afterTick(groupId, runtime.engine);
      }
      return barrier;
    });
    wakeAll();
  } catch (error) {
    runtime.constructionFailed = true;
    log.error(`failed to construct an engine: ${toLogFormat(error)}`);
    wakeAll();
  }
  return runtime.engine;
}

// Every engine built so far, by group id — for the loops that tend all groups (flags,
// scans, catch-up, resets).
export function builtPersonasEngines(): ReadonlyArray<[string, Engine]> {
  const out: Array<[string, Engine]> = [];
  for (const [groupId, runtime] of runtimes) {
    if (runtime.engine) {
      out.push([groupId, runtime.engine]);
    }
  }
  return out;
}

// Warm a group's engine (or, with no group, prepare for engines) so the first
// send/receive is instant and a failure is visible early. A no-op when disabled.
export function warmPersonasEngine(groupId?: string): void {
  if (!isPersonasEngineEnabled()) {
    return;
  }
  // Fetch (or verify) the pinned proving keys first; a no-op without a pinned hash.
  drop(
    (async () => {
      await initPersonasPersistence();
      persistenceReady = true;
      keysReady = await ensureProvingKeys(getKeysDir());
      if (keysReady) {
        if (groupId) {
          getPersonasEngine(groupId);
        }
      } else if (!keysRetry) {
        // Server unreachable or a bad download: try again shortly rather than leaving
        // this member without an engine until the next restart.
        keysRetry = setTimeout(() => {
          keysRetry = undefined;
          warmPersonasEngine(groupId);
        }, KEYS_RETRY_MS);
      }
    })()
  );
}

// What a held post shows until the engine applies it (see `ingestRecordForTimeline`).
export const PENDING_POST_BODY = 'Verifying this post\u2026';

/**
 * A held post, once the engine has applied it: what to show in place of the
 * placeholder. Undefined while it is still held (or if it never applies).
 */
export function appliedPost(
  groupId: string | undefined,
  eh: string
): { body: string; persona?: string; flagged: boolean } | undefined {
  // Peek at what is already built, never build (this runs from a timer).
  const engine = groupId ? runtimes.get(groupId)?.engine : undefined;
  const entry = engine?.logEntry(eh);
  if (!entry || entry.kind !== 'Post') {
    return undefined;
  }
  return { body: entry.body, persona: entry.author, flagged: entry.flagged };
}

// The result of examining an incoming message body for a personas record.
export type RecordIngestResult =
  // Ordinary chatter — let it flow through the normal message pipeline untouched.
  | { kind: 'not-record' }
  // A record that produced nothing to render (a join/vote/rate/scan, or one
  // buffered / rejected) — keep it out of the timeline, but it is not a chat message.
  | { kind: 'ingested' }
  // A post to render: stamp these onto the message and show it as a persona bubble.
  | {
      kind: 'post';
      eh: string;
      persona?: string;
      body: string;
      flagged: boolean;
      // Held by the engine, not yet applied: `body` is a placeholder until it is.
      pending?: boolean;
    }
  // A poll to render as its own bubble. `eh` is the handle a ballot references.
  | { kind: 'poll'; eh: string; descriptor: PersonaPollDescriptor }
  // A badge REQUEST, to render as a notification an admin can approve in place. `eh`
  // is the handle the approval names, so the Approve button needs nothing else.
  //
  // This needs its own kind because the replica logs a request like any other entry,
  // with `kind: "BadgeRequest"` and a body of `"requested badge slot 1"`. Without the
  // branch it fell through to `kind: 'post'` below and every member saw a persona
  // bubble containing that internal string — the "weird automated message" that made
  // the whole flow unexplainable from the UI.
  | { kind: 'badge-request'; eh: string; slot: number }
  // A badge APPROVAL, rendered so the requester learns they have one to collect.
  | { kind: 'badge-approve'; eh: string; slot: number };

// VIEWS (SERVERLESS_PROTOCOL.md §5.5). Every record carries a hash of its sender's view
// of the group, and the engine compares the ones it receives with its own. After each
// ingest we send any records the engine asks us to relay, and tell the member, once per
// episode, if some member's view disagrees with ours.
const viewsDiverged = new Map<string, boolean>();

export function getPersonasViewReport(
  groupId: string | undefined
): ViewReport | undefined {
  return getPersonasEngine(groupId)?.viewReport();
}

// What a barrier can reveal about our own records and the group's views.
function afterTick(groupId: string, currentEngine: Engine): void {
  const lost = currentEngine.takeLost();
  if (lost.length > 0) {
    // The member's object went back to where it was: keep that, then say so.
    persistAfterEmit(groupId, currentEngine);
    log.warn(`the group did not take ${lost.length} of our record(s); object restored`);
    window.reduxActions?.toast?.showToast({
      toastType: ToastType.PersonaRecordLost,
    });
  }
  const foreign = currentEngine.foreignRoots() > 0;
  if (foreign && !foreignRoots.get(groupId)) {
    log.warn('a member named a root we never produced: views of the group differ');
    window.reduxActions?.toast?.showToast({
      toastType: ToastType.PersonaViewsDiverged,
    });
  }
  foreignRoots.set(groupId, foreign);
}

const foreignRoots = new Map<string, boolean>();

async function relayAndCheckViews(
  groupId: string,
  currentEngine: Engine
): Promise<void> {
  const relays = currentEngine.takeRelays();
  if (relays.length > 0) {
    const conversation = window.ConversationController.get(groupId);
    if (conversation) {
      log.warn(`views disagree: relaying ${relays.length} record(s) to the group`);
      for (const relay of relays) {
        // oxlint-disable-next-line no-await-in-loop
        await conversation.enqueueMessageForSend(
          { body: encodeRelayBody(relay.barrier, relay.record), attachments: [] },
          { hideFromTimeline: true }
        );
      }
    }
  }
  const report = currentEngine.viewReport();
  if (report.diverged && !viewsDiverged.get(groupId)) {
    log.warn(
      `views diverged: ${report.mismatches.length} record(s) carry a view of the ` +
        `group that differs from ours (first at barrier ${report.mismatches[0]?.barrier})`
    );
    window.reduxActions?.toast?.showToast({
      toastType: ToastType.PersonaViewsDiverged,
    });
  }
  viewsDiverged.set(groupId, report.diverged);
}

// Receive seam for the timeline: ingest a record body and describe what to render.
// `serverTimestampMs` is the SERVICE receive timestamp; on the shared barrier
// schedule it is what buckets the record onto a barrier every member agrees about
// (see personasBarrier). Never throws. A record body is always kept out of the raw
// timeline (`not-record` is returned only for genuine non-records).
export function ingestRecordForTimeline(
  groupId: string | undefined,
  body: string | undefined | null,
  serverTimestampMs: number
): RecordIngestResult {
  // A relayed record (another member re-sending one Signal may have withheld from us)
  // is ingested at the barrier the relay names, then rendered like any other.
  const relay = decodeRelayBody(body);
  const record = relay?.record ?? decodeRecordBody(body);
  if (!record) {
    return { kind: 'not-record' };
  }
  const currentEngine = getPersonasEngine(groupId);
  if (!currentEngine) {
    log.warn('ingestRecordForTimeline: record arrived but engine unavailable');
    return { kind: 'ingested' };
  }
  try {
    const receivedMs = benchNowMs();
    const receivedAt = ingestTimestampFor(groupId, serverTimestampMs);
    const status: IngestStatus = relay
      ? currentEngine.ingestRelayed(record, relay.barrier, receivedAt)
      : currentEngine.ingest(record, receivedAt);
    if (groupId) {
      drop(relayAndCheckViews(groupId, currentEngine));
    }
    if (isBenchLogEnabled() && groupId) {
      const doneMs = benchNowMs();
      benchLog({
        event: 'receive',
        group: groupTag(groupId),
        key: status.eh,
        kind: opName(currentEngine, status.eh, 'record'),
        status: status.status,
        receivedMs,
        doneMs,
        ingestMs: doneMs - receivedMs,
      });
      benchSettled(groupId, currentEngine);
    }
    log.info(
      `ingested record: ${status.status}${status.reason ? ` (${status.reason})` : ''}`
    );

    // A poll is drawn from its own record, keyed by the eh the engine just gave us,
    // which is the handle a ballot must reference.
    const poll = currentEngine.recordPoll(record);
    if (poll) {
      return {
        kind: 'poll',
        eh: status.eh,
        descriptor: pollDescriptorFromRecord(poll),
      };
    }

    // A post the replica is holding (it names group state we do not have yet, such as
    // a member's join before our catch-up) has no log entry until it applies. Dropping
    // it here lost it for good: it applied later but was never shown. Keep its place
    // with a placeholder; the flag refresher fills it in once it applies.
    if (status.status === 'buffered' && currentEngine.recordKind(record) === 'Post') {
      return {
        kind: 'post',
        eh: status.eh,
        body: PENDING_POST_BODY,
        flagged: false,
        pending: true,
      };
    }

    const entry = currentEngine.logEntry(status.eh);
    if (!entry) {
      return { kind: 'ingested' };
    }

    // Badge records are NOT posts, even though the replica logs them as entries with a
    // body. Branch before the post fallthrough below, or their internal body text gets
    // rendered as somebody's message.
    if (entry.kind === 'BadgeRequest' || entry.kind === 'BadgeApprove') {
      const slot = badgeSlotFromLogBody(entry.body);
      if (slot == null) {
        // The body format is ours, so this should not happen — but guessing a slot
        // would put a wrong badge name in front of an admin about to grant it.
        log.error(
          `ingestRecordForTimeline: could not read a slot out of a ${entry.kind} ` +
            `body (${JSON.stringify(entry.body)}); not rendering it`
        );
        return { kind: 'ingested' };
      }
      return {
        kind: entry.kind === 'BadgeRequest' ? 'badge-request' : 'badge-approve',
        eh: status.eh,
        slot,
      };
    }

    // Only a Post is something to show. Joins, re-join approvals and scans are logged
    // too (a Join's body is its account), and rendering them showed a stranger's
    // account id as an anonymous message.
    if (entry.kind !== 'Post') {
      return { kind: 'ingested' };
    }

    return {
      kind: 'post',
      eh: status.eh,
      persona: entry.author,
      body: entry.body,
      flagged: entry.flagged,
    };
  } catch (error) {
    log.error(`ingestRecordForTimeline failed: ${toLogFormat(error)}`);
    return { kind: 'ingested' };
  }
}

// Move a record of ours to the barrier every other member placed it on.
setOwnRecordSettler(({ groupId, recordBase64 }, serverMs) => {
  try {
    getPersonasEngine(groupId)?.ingest(
      Buffer.from(recordBase64, 'base64'),
      ingestTimestampFor(groupId, serverMs)
    );
  } catch (error) {
    log.error(`could not settle our own record: ${toLogFormat(error)}`);
  }
});

// Whether a record is accepted because of who sent it. Those travel under a real account,
// so their sender is answerable for the timestamp and has no echo to place itself by.
const ATTRIBUTABLE_RECORDS = new Set([
  'Join',
  'RejoinApprove',
  'Ban',
  'BadgeApprove',
]);
export function isAttributableRecord(
  groupId: string | undefined,
  body: string | undefined | null
): boolean {
  const record = decodeRecordBody(body);
  const kind = record && getPersonasEngine(groupId)?.recordKind(record);
  return kind != null && ATTRIBUTABLE_RECORDS.has(kind);
}

// Fold our own record into our replica at the timestamp it will be SENT with, until the
// service's copy says where it really belongs (personasRegistry).
function selfIngest(
  groupId: string,
  currentEngine: Engine,
  emitted: Emitted
): void {
  const sentAt = stampOwnRecord(groupId, Buffer.from(emitted.bytes).toString('base64'));
  currentEngine.ingest(emitted.bytes, ingestTimestampFor(groupId, sentAt));
}

// THE ORDERING RULE (personasPersistence): the member state an emit produced is saved,
// durably, before the record is sent — never after. Throws if it cannot be saved; every
// caller treats that as "do not send".
function persistAfterEmit(groupId: string, currentEngine: Engine): void {
  const state = currentEngine.exportMemberState();
  if (!savePersonasState(groupId, state ? Buffer.from(state) : undefined)) {
    throw new Error('could not save the member state; not sending');
  }
}

// Emit + self-ingest a record (a member's own replica must contain its own records),
// returning the record ready to carry. Used for protocol records (join/rate/vote/scan)
// and dev helpers where the whole body is the record.
export function emitAndSelfIngest(
  groupId: string | undefined,
  produce: (engine: Engine) => Emitted
): { emitted: Emitted; body: string } | undefined {
  const currentEngine = getPersonasEngine(groupId);
  if (!groupId || !currentEngine) {
    return undefined;
  }
  const startMs = benchNowMs();
  const emitted = produce(currentEngine);
  persistAfterEmit(groupId, currentEngine);
  // Our own record never went to the server, so there is no service timestamp;
  // ingestTimestampFor falls back to local wall-clock on the shared schedule (and to
  // the local-barrier 0 when there is no schedule).
  selfIngest(groupId, currentEngine, emitted);
  benchEmitted(
    groupId,
    currentEngine,
    opName(currentEngine, emitted.eh, 'record'),
    startMs,
    emitted.eh
  );
  return { emitted, body: encodeRecordBody(emitted.bytes) };
}

// The fields the send path needs for a persona post: the plaintext to display,
// the persona petname (undefined for anonymous), the envelope hash (the handle a
// rating or ban poll targets), and the base64 record to put on the wire in place of
// the plaintext.
export type PersonaPostSend = {
  body: string;
  persona?: string;
  eh: string;
  personaRecordBase64: string;
};

// Compose a persona post: emit the record (with a real Groth16 proof), self-ingest
// it, and return what to send. The message displays `body` (plaintext) everywhere
// while the wire carries the record — the send path swaps them via
// `personaRecordBase64`. Returns undefined if the engine is unavailable.
// Whether this member has used its posts until a sweep finishes. Its next post could not
// be proved, so it has to be refused here.
export function personaScanRequired(groupId: string | undefined): boolean {
  return getPersonasEngine(groupId)?.scanRequired() ?? false;
}

export function composePersonaPost(
  groupId: string | undefined,
  text: string,
  choice: PersonaChoice
): PersonaPostSend | undefined {
  const currentEngine = getPersonasEngine(groupId);
  if (!groupId || !currentEngine) {
    return undefined;
  }
  let emitted: Emitted;
  const startMs = benchNowMs();
  try {
    if (choice.kind === 'anon') {
      emitted = currentEngine.emitPostAnon(text);
    } else if (choice.kind === 'rate') {
      // Topic-scoped and rate-limited: persona = H(sk || context || index), with
      // index < MAX_PSEUDO. The context comes from the topic registry, so all
      // members derive comparable personas for the same topic.
      emitted = currentEngine.emitPostPseudoRate(
        text,
        choice.context,
        choice.index
      );
    } else {
      // The UNLIMITED plain pseudonym: no topic. A member may mint as many of these
      // as they like, so the fresh random nonce is what makes each one a distinct,
      // unlinkable petname.
      emitted = currentEngine.emitPostPseudo(text, choice.nonce);
    }
    persistAfterEmit(groupId, currentEngine);
  } catch (error) {
    log.error(`composePersonaPost: emit failed: ${toLogFormat(error)}`);
    return undefined;
  }
  // Our own record; no service timestamp exists yet (see emitAndSelfIngest).
  selfIngest(groupId, currentEngine, emitted);
  benchEmitted(
    groupId,
    currentEngine,
    { anon: 'anon_post', pseudo: 'pseudo_post', rate: 'rate_limited_post' }[
      choice.kind
    ],
    startMs,
    emitted.eh
  );
  return {
    body: text,
    persona: emitted.persona ?? undefined,
    eh: emitted.eh,
    personaRecordBase64: Buffer.from(emitted.bytes).toString('base64'),
  };
}

// ---------------------------------------------------------------------------
// The rest of the record surface: rate, poll, vote, scan.
//
// These were reachable only from the engine addon before — nothing in the app
// emitted them, which meant reputation could not move, a poll could not be opened,
// and a ban could not be voted. Each helper emits + self-ingests and returns the body
// to carry; the caller (personasActions) sends it attributably.
// ---------------------------------------------------------------------------

// Rate the record `targetEh` by `delta` (conventionally +1 / -1). Reputation is what
// a ban poll ultimately acts on, so this is the ordinary feedback path.
// Rate the record `targetEh` by `delta`. Like a ballot, this is PSEUDONYMOUS in
// circuit — `member.rate` derives the rater as `H(sk, target.context())` with no
// nonce, giving one rating per member per target, unlinkable across targets. So it
// rides the phantom: an attributable envelope would name the rater outright.
export function composePersonaRate(
  groupId: string | undefined,
  targetEh: string,
  delta: number
): { eh: string; body: string } | undefined {
  const currentEngine = getPersonasEngine(groupId);
  if (!groupId || !currentEngine) {
    return undefined;
  }
  let emitted: Emitted;
  const startMs = benchNowMs();
  try {
    emitted = currentEngine.emitRate(targetEh, delta);
    persistAfterEmit(groupId, currentEngine);
  } catch (error) {
    log.error(`composePersonaRate: emit failed: ${toLogFormat(error)}`);
    return undefined;
  }
  selfIngest(groupId, currentEngine, emitted);
  benchEmitted(groupId, currentEngine, 'rating', startMs, emitted.eh);
  return { eh: emitted.eh, body: encodeRateBody(emitted.bytes) };
}

// Open a poll. A `ban` poll must name the post under review via `targetEh`; option 0
// is the ban option by convention (matching the engine's own e2e test).
export function composePersonaPoll(
  groupId: string | undefined,
  descriptor: PersonaPollDescriptor,
  targetEh?: string
): { eh: string; body: string; descriptor: PersonaPollDescriptor } | undefined {
  const currentEngine = getPersonasEngine(groupId);
  if (!groupId || !currentEngine) {
    return undefined;
  }
  let emitted: Emitted;
  const startMs = benchNowMs();
  try {
    emitted = currentEngine.emitPoll(
      descriptor.question,
      [...descriptor.options],
      descriptor.kind,
      descriptor.kind === 'ban' ? targetEh : undefined
    );
    persistAfterEmit(groupId, currentEngine);
  } catch (error) {
    log.error(`composePersonaPoll: emit failed: ${toLogFormat(error)}`);
    return undefined;
  }
  selfIngest(groupId, currentEngine, emitted);
  benchEmitted(groupId, currentEngine, 'poll', startMs, emitted.eh);
  return {
    eh: emitted.eh,
    body: encodePollBody(emitted.bytes),
    descriptor,
  };
}

// Cast a ballot in the poll named by `pollEh`.
// Cast a ballot in the poll named by `pollEh`.
//
// A ballot is PSEUDONYMOUS, not anonymous: in circuit the voter is
// `H(sk, poll.context())`, and because that derivation takes no nonce a member can
// produce exactly one pseudonym per poll — which is what enforces one vote each. Two
// ballots by the same member in one poll are linkable to each other (by design, that is
// how a double vote is spotted) but not to the account behind them.
//
// The body is VOTE-marked so it rides the phantom, hiding the real Signal sender.
// Without that, the pseudonym would be pointless — the envelope would name the voter.
export function composePersonaVote(
  groupId: string | undefined,
  pollEh: string,
  optionIndex: number
): { eh: string; body: string } | undefined {
  const currentEngine = getPersonasEngine(groupId);
  if (!groupId || !currentEngine) {
    return undefined;
  }
  let emitted: Emitted;
  const startMs = benchNowMs();
  try {
    // The poll's envelope hash IS the poll_id: the engine derives
    // `context = poll.context() = Poseidon(eh)` and the voter's pseudonym as
    // `H(sk, context)`, with no nonce. One pseudonym per poll, hence one vote per
    // member. Nothing else needs passing.
    emitted = currentEngine.emitVote(pollEh, optionIndex);
    persistAfterEmit(groupId, currentEngine);
  } catch (error) {
    log.error(`composePersonaVote: emit failed: ${toLogFormat(error)}`);
    return undefined;
  }
  selfIngest(groupId, currentEngine, emitted);
  benchEmitted(groupId, currentEngine, 'vote', startMs, emitted.eh);
  return { eh: emitted.eh, body: encodeVoteBody(emitted.bytes) };
}

// Absorb the callbacks (revocations, badges, reputation) fired since our last scan.
//
// In two steps, so a scan that went stale while it was being proved is never sent (see
// Messenger::prepare_scan in the engine): prepare (prove; nothing released), check
// `personaScanStillValid` close to sending, then commit — which is the only way to get
// the record to send — or discard. Throws "nothing to scan" when nothing is outstanding.
// When each group's prepared scan started proving (for the experiment log).
const scanStartedMs = new Map<string, number>();

export function preparePersonaScan(
  groupId: string | undefined,
  dummy = false
): string | undefined {
  const currentEngine = getPersonasEngine(groupId);
  if (groupId) {
    scanStartedMs.set(groupId, benchNowMs());
  }
  return currentEngine ? currentEngine.prepareScan(dummy) : undefined;
}

export function personaScanStillValid(groupId: string | undefined): boolean {
  return getPersonasEngine(groupId)?.scanStillValid() ?? false;
}

export function discardPersonaScan(groupId: string | undefined): void {
  getPersonasEngine(groupId)?.discardScan();
}

// Release the prepared scan and save the state it produced, before it is sent.
export function commitPersonaScan(
  groupId: string | undefined
): { eh: string; body: string } | undefined {
  const currentEngine = getPersonasEngine(groupId);
  if (!groupId || !currentEngine) {
    return undefined;
  }
  const emitted = currentEngine.commitScan();
  persistAfterEmit(groupId, currentEngine);
  selfIngest(groupId, currentEngine, emitted);
  benchEmitted(
    groupId,
    currentEngine,
    'scan',
    scanStartedMs.get(groupId) ?? benchNowMs(),
    emitted.eh
  );
  return { eh: emitted.eh, body: encodeScanBody(emitted.bytes) };
}

export const BADGE_SLOTS: ReadonlyArray<{ slot: number; name: string }> = [
  { slot: 1, name: 'Faculty' },
  { slot: 2, name: 'Student' },
  { slot: 3, name: 'Industry' },
];

/**
 * Request a badge. Files a ticket an admin can approve; grants nothing by itself.
 *
 * Attributable on purpose — the requester is asking a human to vouch for them, which
 * is not a claim that can be made anonymously.
 */
export function composeBadgeRequest(
  groupId: string | undefined,
  slot: number
): { eh: string; body: string } | undefined {
  // `encodeBadgeBody`, not the default attributable encoding `emitAndSelfIngest`
  // applies. The marker is the only thing the send splice looks at, so the choice of
  // encoder here IS the choice of whether the requester is named on the wire.
  return emitBadgeRecord(groupId, engine => engine.emitBadgeRequest(slot));
}

/** Approve a badge request by its envelope hash (admin action). Phantom-routed. */
export function composeBadgeApprove(
  groupId: string | undefined,
  requestEh: string,
  slot: number
): { eh: string; body: string } | undefined {
  const approval = emitBadgeRecord(groupId, engine =>
    engine.emitBadgeApprove(requestEh, slot)
  );
  // Under the admin's own account, never the phantom: an approval counts only because
  // of who sent it (recordRefusal), and it names a request, not the person behind it.
  return approval && { eh: approval.eh, body: encodeRecordBody(approval.bytes) };
}

/**
 * Emit + self-ingest a badge record. `body` is the phantom badge carriage, which is what
 * a request travels under.
 */
function emitBadgeRecord(
  groupId: string | undefined,
  produce: (engine: Engine) => Emitted
): { eh: string; body: string; bytes: Uint8Array } | undefined {
  const currentEngine = getPersonasEngine(groupId);
  if (!groupId || !currentEngine) {
    return undefined;
  }
  const startMs = benchNowMs();
  const emitted = produce(currentEngine);
  persistAfterEmit(groupId, currentEngine);
  selfIngest(groupId, currentEngine, emitted);
  benchEmitted(
    groupId,
    currentEngine,
    opName(currentEngine, emitted.eh, 'badge'),
    startMs,
    emitted.eh
  );
  return {
    eh: emitted.eh,
    body: encodeBadgeBody(emitted.bytes),
    bytes: emitted.bytes,
  };
}

/**
 * The badges this member's own zk object contains — the ONLY authority on possession.
 *
 * Empty when the engine is unavailable or the addon predates `getBadges`. That default
 * is the safe one: it under-claims rather than over-claims, so a build that cannot tell
 * sends no badge instead of asserting an unverified one.
 */
export function heldBadges(groupId: string | undefined): ReadonlyArray<string> {
  const engine = getPersonasEngine(groupId);
  if (!engine || typeof engine.getBadges !== 'function') {
    return [];
  }
  try {
    return engine.getBadges();
  } catch (error) {
    log.error(`heldBadges failed: ${toLogFormat(error)}`);
    return [];
  }
}

/** Badge requests awaiting approval, read from the replica's own log. */
export function listPendingBadgeRequests(
  groupId: string | undefined
): ReadonlyArray<{
  eh: string;
  slot: number;
}> {
  const engine = getPersonasEngine(groupId);
  if (!engine || typeof engine.pendingBadgeRequests !== 'function') {
    return [];
  }
  try {
    return engine.pendingBadgeRequests();
  } catch (error) {
    log.error(`listPendingBadgeRequests failed: ${toLogFormat(error)}`);
    return [];
  }
}

/**
 * Prove we hold `badge`, by name. Undefined if we do not hold it — the proof is simply
 * unsatisfiable, which is the point: a badge label can be typed, a badge proof cannot.
 */
export function composeBadgeProof(
  groupId: string | undefined,
  badge: string
): Uint8Array | undefined {
  const engine = getPersonasEngine(groupId);
  if (!engine || typeof engine.emitBadgeProof !== 'function') {
    log.error('composeBadgeProof: addon has no emitBadgeProof binding');
    return undefined;
  }
  try {
    return engine.emitBadgeProof(badge);
  } catch (error) {
    log.error(`composeBadgeProof failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Verify a badge proof and return the badge NAME it proves.
 *
 * Render this, never a label from the message — otherwise a valid Student proof could
 * be displayed as Faculty and the checkmark would be true while the label lied.
 */
export function verifyBadgeProof(
  groupId: string | undefined,
  proof: Uint8Array
): string | undefined {
  const engine = getPersonasEngine(groupId);
  if (!engine || typeof engine.verifyBadgeProof !== 'function') {
    return undefined;
  }
  try {
    return engine.verifyBadgeProof(Buffer.from(proof)) ?? undefined;
  } catch (error) {
    log.error(`verifyBadgeProof failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Produce a ZK proof that two of our own pseudonyms share an author.
 *
 * Contexts, not petnames: for an unlimited pseudonym the context IS the nonce the UI
 * already stores, and the claimed pseudonyms are derived from our secret key inside the
 * circuit — so this cannot assert anything about a persona we do not hold.
 *
 * Unlike the other compose helpers this does NOT self-ingest, because an authorship
 * proof is not a record: nothing is folded into the replica, no accept rule applies,
 * and there is no echo to absorb.
 */
export function composePersonaAuthorship(
  groupId: string | undefined,
  contextA: number,
  contextB: number
): { body: string; proof: Uint8Array } | undefined {
  const engine = getPersonasEngine(groupId);
  if (!engine || typeof engine.emitAuthorship !== 'function') {
    log.error('composePersonaAuthorship: addon has no emitAuthorship binding');
    return undefined;
  }
  try {
    const startMs = benchNowMs();
    const proof = engine.emitAuthorship(contextA, contextB);
    if (groupId) {
      benchEmitted(
        groupId,
        engine,
        'authorship',
        startMs,
        benchProofKey(proof)
      );
    }
    // Both: `body` for the wire, `proof` so the caller can verify its own output
    // before sending and render from the verifier rather than from its own inputs.
    return { body: encodeAuthorshipProof(proof), proof };
  } catch (error) {
    log.error(`composePersonaAuthorship failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Prove possession of `badge` in zero knowledge.
 *
 * Unsatisfiable if this member's object does not actually hold it, which is the whole
 * value of this over the decorative label: a label is a string anyone can type, a proof
 * only exists if an admin approved the badge and the member scanned it in.
 *
 * Not a record, so it does not self-ingest — nothing is folded into the replica and no
 * accept rule applies. Same shape as `composePersonaAuthorship`.
 */
export function composePersonaBadgeProof(
  groupId: string | undefined,
  badge: string
): { body: string; proof: Uint8Array } | undefined {
  const engine = getPersonasEngine(groupId);
  if (!engine || typeof engine.emitBadgeProof !== 'function') {
    log.error('composePersonaBadgeProof: addon has no emitBadgeProof binding');
    return undefined;
  }
  try {
    const startMs = benchNowMs();
    const proof = engine.emitBadgeProof(badge);
    if (groupId) {
      benchEmitted(
        groupId,
        engine,
        'badge_proof',
        startMs,
        benchProofKey(proof)
      );
    }
    return { body: encodeBadgeProof(proof), proof };
  } catch (error) {
    // Includes the expected case: we do not hold the badge, so the witness does not
    // exist. Logged rather than thrown — the caller turns it into a visible reason.
    log.error(`composePersonaBadgeProof failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Verify a badge proof and return the badge NAME it proves.
 *
 * The name comes from the proof's public inputs via the addon's own lookup, never from
 * the message. A proof that verifies but maps to no known badge value returns undefined
 * rather than a plausible-looking guess.
 */
export function verifyPersonaBadgeProof(
  groupId: string | undefined,
  proof: Uint8Array
): string | undefined {
  const engine = getPersonasEngine(groupId);
  if (!engine || typeof engine.verifyBadgeProof !== 'function') {
    return undefined;
  }
  try {
    const startMs = benchNowMs();
    const badge = engine.verifyBadgeProof(Buffer.from(proof)) ?? undefined;
    const doneMs = benchNowMs();
    benchLog({
      event: 'verify',
      op: 'badge_proof',
      key: benchProofKey(proof),
      ms: doneMs - startMs,
      doneMs,
      ok: badge != null,
    });
    return badge;
  } catch (error) {
    log.error(`verifyPersonaBadgeProof failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Verify an authorship proof and return the names it PROVES about.
 *
 * The names come from the proof's own public inputs, never from the message. That is
 * the whole point: a sender holding a valid proof about two pseudonyms they own could
 * otherwise display it beside someone else's persona names, and the checkmark would be
 * true while the statement was false.
 */
export function verifyPersonaAuthorship(
  groupId: string | undefined,
  proof: Uint8Array
): { first: string; second: string } | undefined {
  const engine = getPersonasEngine(groupId);
  if (!engine || typeof engine.verifyAuthorship !== 'function') {
    return undefined;
  }
  try {
    const startMs = benchNowMs();
    const names = engine.verifyAuthorship(Buffer.from(proof)) ?? undefined;
    const doneMs = benchNowMs();
    benchLog({
      event: 'verify',
      op: 'authorship',
      key: benchProofKey(proof),
      ms: doneMs - startMs,
      doneMs,
      ok: names != null,
    });
    return names;
  } catch (error) {
    log.error(`verifyPersonaAuthorship failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

// The engine's own status line for a poll, if it publishes one we can match. Used as
// the poll bubble's status text so the tally shown is the ENGINE's, never something
// the UI derived on its own. Matched defensively (the line format is the engine's to
// choose) and simply absent when no line matches.
// Called from a REDUX SELECTOR (getPropsForMessage), which means it runs synchronously
// on the renderer's main thread, potentially on every store update, once per poll
// message on screen. Two consequences, both learned the hard way:
//
//  1. It must NEVER construct the engine. `getPersonasEngine()` builds lazily, and
//     construction reads the ~51 MB key bundle (and GENERATES it, taking minutes, if the
//     cache is cold). Doing that inside a selector blocks the first paint, so the window
//     opens and then sits blank — with no error, because nothing threw. An instance whose
//     history contains a persona poll hits this; one whose history does not, does not,
//     which is why some instances looked fine and others hung.
//  2. `renderPolls()` is a native call that walks the replica. Calling it per render per
//     poll is wasteful even once the engine is warm, so the result is memoised for a
//     short window — long enough to collapse a burst of renders, short enough that a
//     moving tally still updates promptly.
const POLL_STATUS_TTL_MS = 500;
const pollStatusCache = new Map<
  string,
  { atMs: number; lines: ReadonlyArray<string> }
>();

export function getPollStatusLine(
  groupId: string | undefined,
  pollEh: string
): string | undefined {
  // Deliberately NOT getPersonasEngine(): peek at what is already built, never build.
  const engine = groupId ? runtimes.get(groupId)?.engine : undefined;
  if (!groupId || !engine) {
    return undefined;
  }
  try {
    const now = Date.now();
    let cached = pollStatusCache.get(groupId);
    if (!cached || now - cached.atMs > POLL_STATUS_TTL_MS) {
      cached = { atMs: now, lines: engine.renderPolls() };
      pollStatusCache.set(groupId, cached);
    }
    const shortEh = pollEh.slice(0, 12);
    return cached.lines.find(
      line => line.includes(pollEh) || line.includes(shortEh)
    );
  } catch (error) {
    log.error(`getPollStatusLine failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

// Whether the post named by `eh` is currently flagged (its author's persona was
// revoked). The receive path stamps `personaFlagged` at ingest time, but a ban that
// settles LATER has to be re-read from the engine — this is what the flag refresher
// polls. Returns undefined when the engine has no entry for `eh`.
export function isPostFlagged(
  groupId: string | undefined,
  eh: string
): boolean | undefined {
  const currentEngine = getPersonasEngine(groupId);
  if (!currentEngine) {
    return undefined;
  }
  try {
    return currentEngine.logEntry(eh)?.flagged;
  } catch (error) {
    log.error(`isPostFlagged failed: ${toLogFormat(error)}`);
    return undefined;
  }
}
