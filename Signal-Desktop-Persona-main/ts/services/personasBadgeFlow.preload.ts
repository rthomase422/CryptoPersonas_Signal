// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The badge REQUEST -> ADMIN APPROVAL -> SCAN flow.
//
// A badge differs from everything else in this demo in one important way: it is the only
// claim that needs a second party. A pseudonym, an authorship proof and a reputation
// score are all statements about your own keys, so you can produce them alone. A badge
// says "someone vouched for me", so somebody else has to act.
//
// The protocol path, all of which already exists:
//
//   1. requester emits `Record::BadgeRequest`, which FILES A CALLBACK. The callback is
//      the thing approval invokes — without it there would be nothing to approve.
//   2. an admin emits `Record::BadgeApprove` naming the request's envelope hash. Its
//      accept rule marks the requester's ticket with the approved slot.
//   3. at the next settlement barrier the replica invokes that ticket with
//      BADGE1/2/3_FLAG — the same machinery that invokes BAN_FLAG for a ban.
//   4. the requester's next SCAN absorbs it, and the circuit writes the badge into
//      their own user object (`standard_callback_method`).
//   5. only then can they prove possession with `badge_pred`.
//
// So a badge is not granted at approval time. It lands at the requester's next scan,
// exactly like a ban — and the UI has to say so, because "approved" and "usable" are
// several seconds and one scan apart.
//
// BOTH RECORDS RIDE THE SHARED PHANTOM, so neither the requester nor the approver is
// named on the wire.
//
// They started out attributable, on the argument that "a request is a person asking a
// human to vouch for them, which cannot be done anonymously". That argument was wrong
// about this protocol. Look at steps 1-4 above: the grant travels by CALLBACK. The
// approval names a ticket, the replica invokes it, the requester absorbs it because they
// alone hold the secret. Identity never enters the chain, so attributing the envelope
// was leaking something nothing used.
//
// THE COST, which is real: an admin approves "a request for Faculty", not "Bob's
// request". They cannot recognise who they are vouching for. If person-specific
// vouching turns out to be required, the fix is to change the marker back in
// personasCarriage.std.ts — deliberately, and knowing what it reveals — not to relabel
// the bubble.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  ensureReadyForPersonaAction,
  ensureReadyForUnprovenRecord,
} from './personasActions.preload.ts';
import {
  BADGE_SLOTS,
  composeBadgeApprove,
  composeBadgeRequest,
  isPersonasEngineEnabled,
  listPendingBadgeRequests,
} from './personasEngine.preload.ts';

const log = createLogger('personasBadgeFlow');

export { BADGE_SLOTS };

/**
 * Outcome of a badge action, carrying the REASON on failure.
 *
 * A boolean was not enough. Both of these calls can fail for at least four materially
 * different reasons — a callback sweep is unfinished, the engine has no replica yet, the
 * slot is wrong, or the addon threw — and a boolean collapsed all of them into the
 * generic "Something went wrong" toast. The fix for each is different, so the reason has
 * to reach the person pressing the button.
 */
export type BadgeFlowResult =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * The message from a thrown engine error, for display.
 *
 * napi errors carry a useful `message` (e.g. the refusal from `guard_not_scanning`), so
 * that is what to show. Anything without one falls back to a string form rather than
 * rendering "[object Object]".
 */
function reasonFor(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return String(error);
}

/** The badge name for a slot, for rendering a request without a lookup table in the UI. */
export function badgeNameForSlot(slot: number): string {
  return BADGE_SLOTS.find(b => b.slot === slot)?.name ?? `slot ${slot}`;
}

/**
 * Ask for a badge. Grants nothing: it files the ticket an admin can approve.
 *
 * Shown in the timeline as a notification, on every side. It was hidden originally, on
 * the theory that it was coordination traffic — but that made the flow unusable: an
 * admin saw an unexplained record arrive with no way to act on it, and the requester
 * got no acknowledgement at all. A request is a social act, so it is rendered where it
 * was made, with the Approve button attached to it (PersonaBadgeNotice). The status
 * panel keeps a list as a backstop for requests that have scrolled away.
 */
export async function requestBadge(
  conversation: ConversationModel,
  slot: number
): Promise<BadgeFlowResult> {
  if (!isPersonasEngineEnabled()) {
    return { ok: false, reason: 'the personas engine is not enabled' };
  }
  if (!BADGE_SLOTS.some(b => b.slot === slot)) {
    log.error(`requestBadge: ${slot} is not a known badge slot`);
    return { ok: false, reason: `${slot} is not a known badge slot` };
  }
  try {
    // JOIN FIRST, atomically. A BadgeRequest is a member record, so it needs this
    // instance to be on the bulletin — and until this call was added, the badge path
    // was the ONLY persona action that did not join itself. Posting, rating and voting
    // all funnel through `ensurePersonaJoined`; requesting a badge did not, which is
    // why it failed with "this member is not on the bulletin yet" and why sending an
    // ordinary message first appeared to be a prerequisite. It never was: the post was
    // simply doing the join that this function should have done.
    if (!(await ensureReadyForPersonaAction(conversation))) {
      log.warn('requestBadge: could not join; refusing to request');
      return {
        ok: false,
        reason:
          'could not join the bulletin (sealed sender may not be ready yet) — try again in a moment',
      };
    }
    const request = composeBadgeRequest(conversation.get('groupId'), slot);
    if (!request) {
      log.error('requestBadge: could not emit the request record');
      return {
        ok: false,
        reason: 'the engine is unavailable (not joined, or no replica yet)',
      };
    }
    // Shown to the requester too, not hidden. `hideFromTimeline` is sender-local, so
    // hiding it here only ever hid it from the one person who already knew they had
    // asked, while every recipient still rendered something. The notification is the
    // UI for this flow on both sides.
    await conversation.enqueueMessageForSend({
      body: undefined,
      attachments: [],
      personaCarriageBody: request.body,
      // Anonymous on our own copy too, matching every recipient's view.
      personaAnonymous: true,
      personaBadgeNotice: { kind: 'request', eh: request.eh, slot },
    });
    log.info(
      `requestBadge: requested ${badgeNameForSlot(slot)} (eh ${request.eh.slice(0, 12)}…)`
    );
    return { ok: true };
  } catch (error) {
    log.error(`requestBadge failed: ${toLogFormat(error)}`);
    return { ok: false, reason: reasonFor(error) };
  }
}

/**
 * Approve a pending badge request (admin action).
 *
 * Gated on Signal's group-admin role in the UI only. Nothing in the replica's accept
 * rule checks that the sender is an admin, so a modified client could approve itself —
 * the same honest limitation as the ban button, and it is stated in the status panel.
 */
export async function approveBadge(
  conversation: ConversationModel,
  requestEh: string,
  slot: number
): Promise<BadgeFlowResult> {
  if (!isPersonasEngineEnabled()) {
    return { ok: false, reason: 'the personas engine is not enabled' };
  }
  try {
    // ALREADY HANDLED? Checked against the replica, before emitting anything.
    //
    // A second approval of the same slot is in fact harmless — the accept rule just
    // sets `out.badge_slot = Some(slot)` again on the one ticket, so there is no double
    // grant and no double settlement. But it is not harmless in general, and the reason
    // is worth writing down: `badge_slot` is LAST-WRITER-WINS. Two approvals naming
    // DIFFERENT slots for the same request would silently replace the first grant with
    // the second. The UI only ever offers the request's own slot, so that is not
    // reachable today; it is one careless caller away from being reachable, and it
    // would fail silently.
    //
    // So refuse here rather than relying on the button being hidden: the UI's `pending`
    // flag is recomputed on render, which is exactly the kind of guarantee that lapses
    // under a fast double-click.
    if (!isBadgeRequestPending(conversation.get('groupId'), requestEh)) {
      log.warn(
        `approveBadge: ${requestEh.slice(0, 12)}… is not pending (already approved, ` +
        'dismissed, or unknown); refusing to emit a second approval'
      );
      return {
        ok: false,
        reason: 'that request has already been handled',
      };
    }
    // The approving ADMIN has to be on the bulletin too — an approval is a record like
    // any other. An admin who had not posted yet could not approve anything, which is
    // the same missing join seen from the other side.
    if (!(await ensureReadyForUnprovenRecord(conversation))) {
      log.warn('approveBadge: could not join; refusing to approve');
      return {
        ok: false,
        reason:
          'could not join the bulletin (sealed sender may not be ready yet) — try again in a moment',
      };
    }
    const approval = composeBadgeApprove(conversation.get('groupId'), requestEh, slot);
    if (!approval) {
      log.error('approveBadge: could not emit the approval record');
      return {
        ok: false,
        reason: 'the engine is unavailable (not joined, or no replica yet)',
      };
    }
    await conversation.enqueueMessageForSend({
      body: undefined,
      attachments: [],
      personaCarriageBody: approval.body,
      // `approval.eh`, not `requestEh`: the notice identifies THIS record. The request's
      // own notification is what stops showing an Approve button, and it does so because
      // `pendingBadgeRequests()` no longer lists it — not because of anything stored here.
      personaBadgeNotice: { kind: 'approve', eh: approval.eh, slot },
    });
    log.info(
      `approveBadge: approved ${badgeNameForSlot(slot)} for request ${requestEh.slice(0, 12)}…`
    );
    return { ok: true };
  } catch (error) {
    log.error(`approveBadge failed: ${toLogFormat(error)}`);
    return { ok: false, reason: reasonFor(error) };
  }
}

// Requests this admin has DISMISSED, by envelope hash.
//
// ============================================================================
// DISMISSAL IS LOCAL. IT IS NOT A PROTOCOL DENY.
// ============================================================================
//
// There is no `Record::BadgeDeny`. Nothing is broadcast, no other admin learns of it,
// and the requester is not told. All this does is take the request off THIS admin's
// screen so a queue can be worked through.
//
// It is implemented this way, rather than as a record, because the honest alternatives
// were worse. A button that broadcast nothing while being labelled "Deny" would promise
// the requester a refusal that never arrived. A real deny needs a record kind, an accept
// rule that retires the ticket, and a rebuilt addon — worth doing, and specced in the
// workplan, but it is not something to fake in the meantime. So the UI says "Dismiss",
// and says what it does.
//
// Session-scoped on purpose: it matches the lifetime of the thing it filters. The
// replica's log lives in memory and a relaunch re-joins from scratch, so persisting
// dismissals would outlive the requests they refer to.
const dismissed = new Set<string>();

/**
 * Take a request off this admin's queue. Local only — see `dismissed` above.
 *
 * Returns false if it was not pending in the first place, so the caller can tell
 * "dismissed it" from "there was nothing to dismiss".
 */
export function dismissBadgeRequest(
  groupId: string | undefined,
  requestEh: string
): boolean {
  if (!isBadgeRequestPending(groupId, requestEh)) {
    return false;
  }
  dismissed.add(requestEh);
  log.info(
    `dismissBadgeRequest: ${requestEh.slice(0, 12)}… hidden LOCALLY; it remains ` +
    'pending for every other admin and the requester was not notified'
  );
  return true;
}

/**
 * Is this request still awaiting approval?
 *
 * Asked of the REPLICA, not of message state, so an approval cast on any instance
 * retires the Approve button everywhere. Caching "pending" onto the request message at
 * receive time would have left a button that still worked and did nothing, on every
 * admin's screen except the one who clicked it.
 */
export function isBadgeRequestPending(
  groupId: string | undefined,
  requestEh: string
): boolean {
  if (dismissed.has(requestEh)) {
    return false;
  }
  return listPendingBadgeRequests(groupId).some(r => r.eh === requestEh);
}

/** A group's pending requests, newest last, as the admin UI should list them. */
export function pendingBadgeRequests(groupId: string | undefined): ReadonlyArray<{
  eh: string;
  slot: number;
  name: string;
}> {
  return listPendingBadgeRequests(groupId)
    .filter(r => !dismissed.has(r.eh))
    .map(r => ({
      ...r,
      name: badgeNameForSlot(r.slot),
    }));
}
