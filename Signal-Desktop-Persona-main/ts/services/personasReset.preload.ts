// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — admin-approved RESET (one join per account, plus re-joins an admin
// allows).
//
// Every replica accepts ONE join per Signal account (the join's proof binds the account,
// and `recordSenderProblem` below refuses a join whose account is not its sender). That
// stops one person holding several memberships, and stops a banned member from walking
// away from the ban with a fresh identity. But a member can genuinely need a fresh start
// — its object fell off the bulletin, or its saved state was lost — so:
//
//   1. the member REQUESTS a reset: an attributable message to the group (PZX1:) naming
//      its account and carrying a proof that its current object is NOT BANNED and has
//      just completed a scan sweep (so every ban settled so far was absorbed);
//   2. a Signal group ADMIN reviews it — the panel says whether the proof verified
//      against the group's own tree — and APPROVES: a RejoinApprove record, sent under
//      the admin's own account; every member ingests it only from an admin;
//   3. once the approval is in its replica, and one barrier has passed (records in one
//      barrier are ordered by hash, not arrival, so the join must land in a later one),
//      the member resets to a fresh object and joins again. The approval is used up.
//
// A reset keeps the member's secret key, so its pseudonyms stay its own and it cannot vote
// or rate twice. Approving spends the old object, so it cannot stay in use beside the new
// one. A member who has lost its key cannot rejoin the group, because every replica ties
// an account to the key it first joined with.
//
// What it cannot do: a ban decided AFTER the reset on one of the old object's posts
// lands on the abandoned object. The proof narrows that to bans not yet settled at request
// time; the admin's judgement covers the rest.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  emitAndSelfIngest,
  getPersonasEngine,
  groupIdOf,
} from './personasEngine.preload.ts';
import {
  decodeRecordBody,
  encodeResetRequest,
  type PersonaResetRequestWire,
} from './personasCarriage.std.ts';
import {
  forgetPersonaJoin,
  ensurePersonaJoined,
  ourPersonasAccount,
} from './personasMembership.preload.ts';
import {
  personasExtrasChanged,
  registerPersistedExtra,
  savePersonasState,
} from './personasPersistence.preload.ts';

const log = createLogger('personasReset');

// --- our own request ------------------------------------------------------------------

type OwnRequest = {
  requestedAt: number;
  // The barrier at which the approval was first seen in our replica; we re-join only
  // in a LATER barrier.
  approvedAtBarrier?: number;
};

// Per personas group: a reset is a new member IN THAT GROUP.
const ownRequests = new Map<string, OwnRequest>();

registerPersistedExtra('resetRequest', {
  snapshot: groupId => ownRequests.get(groupId) ?? null,
  restore: (groupId, value) => {
    const v = value as Partial<OwnRequest> | null;
    if (v && typeof v.requestedAt === 'number') {
      ownRequests.set(groupId, {
        requestedAt: v.requestedAt,
        ...(typeof v.approvedAtBarrier === 'number'
          ? { approvedAtBarrier: v.approvedAtBarrier }
          : {}),
      });
    } else {
      ownRequests.delete(groupId);
    }
  },
});

export type ResetState = 'none' | 'requested' | 'approved';

export function ownResetState(groupId: string | undefined): ResetState {
  const ownRequest = groupId ? ownRequests.get(groupId) : undefined;
  if (!ownRequest) {
    return 'none';
  }
  return ownRequest.approvedAtBarrier != null ? 'approved' : 'requested';
}

/**
 * Ask the group's admins to allow this account one more join. Makes the "not banned,
 * just swept" proof first — sweeping if needed, which absorbs any ban already settled —
 * and sends the request anyway, without a proof, if one cannot be made (the admin is
 * told why).
 */
export async function requestPersonasReset(
  conversation: ConversationModel,
  sweep: () => Promise<boolean>
): Promise<{ ok: true; proved: boolean } | { ok: false; reason: string }> {
  const groupId = groupIdOf(conversation);
  const engine = getPersonasEngine(groupId);
  const account = ourPersonasAccount();
  if (!groupId || !engine || !account) {
    return { ok: false, reason: 'the personas engine is not ready' };
  }

  let proof: string | null = null;
  let reason: string | undefined;
  const tryProve = () => {
    try {
      proof = Buffer.from(engine.proveNotBanned(account)).toString('base64');
      return true;
    } catch (error) {
      reason = String(error instanceof Error ? error.message : error);
      return false;
    }
  };
  if (!tryProve() && (reason ?? '').includes('full scan')) {
    // Finish a sweep (absorbing anything settled), then try again.
    if (await sweep()) {
      tryProve();
    }
  }

  const wire: PersonaResetRequestWire = {
    a: account,
    p: proof,
    ...(proof == null && reason ? { r: reason.slice(0, 200) } : {}),
  };
  try {
    await conversation.enqueueMessageForSend(
      { body: encodeResetRequest(wire), attachments: [] },
      { hideFromTimeline: true }
    );
  } catch (error) {
    return { ok: false, reason: `could not send the request: ${toLogFormat(error)}` };
  }
  ownRequests.set(groupId, { requestedAt: Date.now() });
  personasExtrasChanged(groupId);
  log.info(`requestPersonasReset: sent (${proof ? 'with' : 'WITHOUT'} a not-banned proof)`);
  return { ok: true, proved: proof != null };
}

/**
 * Run on every flag-loop tick, for every group with a pending request: once an admin's
 * approval for our account is in that group's replica, wait for the next barrier, then
 * become a fresh member there and join again.
 */
export async function maybeCompletePersonasReset(): Promise<void> {
  for (const groupId of [...ownRequests.keys()]) {
    try {
      // oxlint-disable-next-line no-await-in-loop
      await completePersonasResetIfApproved(groupId);
    } catch (error) {
      log.error(`maybeCompletePersonasReset failed: ${toLogFormat(error)}`);
    }
  }
}

async function completePersonasResetIfApproved(groupId: string): Promise<void> {
  const ownRequest = ownRequests.get(groupId);
  const engine = getPersonasEngine(groupId);
  const account = ourPersonasAccount();
  if (!ownRequest || !engine || !account) {
    return;
  }
  const { joins, approved } = engine.joinCounts(account);
  if (joins >= 1 + approved) {
    return; // not approved (yet)
  }
  const barrier = engine.currentBarrier();
  if (ownRequest.approvedAtBarrier == null) {
    ownRequest.approvedAtBarrier = barrier;
    personasExtrasChanged(groupId);
    log.info(`maybeCompletePersonasReset: approved; re-joining after barrier ${barrier}`);
    return;
  }
  if (barrier <= ownRequest.approvedAtBarrier) {
    return;
  }
  const conversation = window.ConversationController.get(groupId);
  if (!conversation) {
    return;
  }

  engine.resetMember();
  forgetPersonaJoin(groupId);
  ownRequests.delete(groupId);
  // Save the fresh object before anything is sent (the ordering rule).
  const state = engine.exportMemberState();
  savePersonasState(groupId, state ? Buffer.from(state) : undefined);
  log.warn('maybeCompletePersonasReset: reset to a fresh member; joining again');
  await ensurePersonaJoined(conversation);
}

// --- requests we receive (admins act on them) -----------------------------------------

export type ReceivedResetRequest = {
  account: string;
  name: string;
  proofOk: boolean;
  reason?: string;
  // The proof as received (base64), kept so it can be checked again: see
  // `checkResetProof`.
  proof?: string;
  at: number;
};

const PROOF_NOT_YET =
  'not verified yet \u2014 it was made against group state this device does not have. ' +
  'Usually their latest scan has not arrived here yet (it is re-checked ' +
  'automatically); if it stays like this, they are out of sync with the group.';

// A proof is only accepted against a tree OUR replica produced. The requester's last
// step before asking is a scan, which changes its tree, and that scan travels on the
// phantom while the request travels under their own account: two senders, no ordering
// between them. So the request often arrives first and cannot verify YET. Keep the
// proof and try again whenever the list is read; once verified it stays verified.
function checkResetProof(
  groupId: string,
  account: string,
  proof: string | undefined
): boolean {
  const engine = getPersonasEngine(groupId);
  if (!proof || !engine) {
    return false;
  }
  try {
    return engine.verifyNotBanned(Buffer.from(proof, 'base64')) === account;
  } catch {
    return false;
  }
}

// Per personas group: account -> the request it sent there.
const receivedByGroup = new Map<string, Map<string, ReceivedResetRequest>>();

function receivedIn(groupId: string): Map<string, ReceivedResetRequest> {
  let received = receivedByGroup.get(groupId);
  if (!received) {
    received = new Map();
    receivedByGroup.set(groupId, received);
  }
  return received;
}

registerPersistedExtra('resetRequestsReceived', {
  snapshot: groupId => [...receivedIn(groupId).values()],
  restore: (groupId, value) => {
    if (!Array.isArray(value)) {
      return;
    }
    const received = receivedIn(groupId);
    for (const r of value as Array<Partial<ReceivedResetRequest>>) {
      if (typeof r.account === 'string' && typeof r.name === 'string') {
        received.set(r.account, {
          account: r.account,
          name: r.name,
          proofOk: r.proofOk === true,
          ...(typeof r.reason === 'string' ? { reason: r.reason } : {}),
          ...(typeof r.proof === 'string' ? { proof: r.proof } : {}),
          at: typeof r.at === 'number' ? r.at : Date.now(),
        });
      }
    }
  },
});

const accountOf = (serviceId: string | undefined) =>
  serviceId?.replaceAll('-', '').toLowerCase();

/** Receive seam: a reset request in group `groupId` from `senderServiceId`. */
export function ingestResetRequest(
  groupId: string | undefined,
  wire: PersonaResetRequestWire,
  senderServiceId: string | undefined
): void {
  if (!groupId) {
    return;
  }
  if (accountOf(senderServiceId) !== wire.a) {
    log.warn('ingestResetRequest: the request names another account than its sender; dropped');
    return;
  }
  // Verifies the proof AND that it was made against our own tree.
  const proofOk = checkResetProof(groupId, wire.a, wire.p ?? undefined);
  const name =
    (senderServiceId &&
      window.ConversationController.get(senderServiceId)?.getTitle()) ||
    'a member';
  receivedIn(groupId).set(wire.a, {
    account: wire.a,
    name,
    proofOk,
    ...(proofOk ? {} : { reason: wire.p ? PROOF_NOT_YET : (wire.r ?? 'no proof') }),
    ...(wire.p ? { proof: wire.p } : {}),
    at: Date.now(),
  });
  personasExtrasChanged(groupId);
  log.info(`ingestResetRequest: from ${name} (${proofOk ? 'not-banned proof verified' : 'NOT proved'})`);
}

export function listResetRequests(
  groupId: string | undefined
): ReadonlyArray<ReceivedResetRequest> {
  if (!groupId) {
    return [];
  }
  const engine = getPersonasEngine(groupId);
  const received = receivedIn(groupId);
  let changed = false;
  for (const r of received.values()) {
    if (!r.proofOk && r.proof && checkResetProof(groupId, r.account, r.proof)) {
      r.proofOk = true;
      delete r.reason;
      changed = true;
    }
  }
  if (changed) {
    personasExtrasChanged(groupId);
  }
  return [...received.values()].filter(r => {
    // Drop requests that are already approved (the account may join again).
    if (!engine) {
      return true;
    }
    const { joins, approved } = engine.joinCounts(r.account);
    return joins >= 1 + approved;
  });
}

/** Whether we are waiting on an admin to approve our own reset. */
export function hasOwnResetRequest(groupId: string): boolean {
  return ownRequests.has(groupId);
}

/**
 * As an admin: allow `account` one more join. Sent under our own account. Approving spends
 * the object named by the request's proof, when it has a verified one.
 */
export async function approvePersonasReset(
  conversation: ConversationModel,
  account: string
): Promise<{ ok: true } | { ok: false; reason: string }> {
  if (!conversation.areWeAdmin()) {
    return { ok: false, reason: 'only a group admin can approve a reset' };
  }
  const groupId = groupIdOf(conversation);
  const request = groupId ? receivedIn(groupId).get(account) : undefined;
  const proof = request?.proofOk ? request.proof : undefined;
  try {
    const result = emitAndSelfIngest(groupId, engine =>
      engine.emitRejoinApprove(account, proof ? Buffer.from(proof, 'base64') : null)
    );
    if (!result) {
      return { ok: false, reason: 'the personas engine is not ready' };
    }
    // Attributable on purpose (PZR2 marker): every member checks it came from an admin.
    await conversation.enqueueMessageForSend(
      { body: result.body, attachments: [] },
      { hideFromTimeline: true }
    );
  } catch (error) {
    return { ok: false, reason: toLogFormat(error) };
  }
  if (groupId) {
    receivedIn(groupId).delete(account);
    personasExtrasChanged(groupId);
  }
  log.info('approvePersonasReset: approval sent');
  return { ok: true };
}

export function dismissResetRequest(groupId: string | undefined, account: string): void {
  if (!groupId) {
    return;
  }
  receivedIn(groupId).delete(account);
  personasExtrasChanged(groupId);
}

// --- the receive-side sender checks ------------------------------------------------------

/**
 * Why a received record must be DROPPED before ingest, or undefined to ingest it. A
 * join must come from the account it names (so nobody can spend another account's one
 * join), and a re-join approval must come from a group admin. Every member sees the same
 * sender and the same admin list, so they all decide the same way.
 */
export function recordSenderProblem(
  body: string | undefined | null,
  senderServiceId: string | undefined,
  conversation: ConversationModel
): string | undefined {
  const record = decodeRecordBody(body);
  const engine = getPersonasEngine(groupIdOf(conversation));
  if (!record || !engine) {
    return undefined;
  }
  const claim = engine.recordAccountClaim(record);
  if (!claim) {
    return undefined;
  }
  if (claim.kind === 'join' && accountOf(senderServiceId) !== claim.account) {
    return 'a join for another account than its sender';
  }
  if (
    claim.kind === 'rejoin-approve' &&
    !(senderServiceId && conversation.isAdmin(senderServiceId as never))
  ) {
    return 'a re-join approval from someone who is not a group admin';
  }
  if (
    claim.kind === 'ban' &&
    !(senderServiceId && conversation.isAdmin(senderServiceId as never))
  ) {
    return 'a ban from someone who is not a group admin';
  }
  if (
    claim.kind === 'badge-approve' &&
    !(senderServiceId && conversation.isAdmin(senderServiceId as never))
  ) {
    return 'a badge approval from someone who is not a group admin';
  }
  return undefined;
}
