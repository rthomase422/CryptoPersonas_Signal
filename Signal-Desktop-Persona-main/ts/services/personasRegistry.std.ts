// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: the envelope-hash -> messageId registry, deliberately kept in its own
// dependency-free module.
//
// The flag refresher (personasFlags) needs this map, and so do the two places that
// learn about a persona post: the receive seam and `enqueueMessageForSend` on the
// conversation model. But personasFlags transitively pulls in the ZK engine, which
// `require`s the native addon at module load and THROWS if the platform binary is
// absent. `ts/models/conversations.preload.ts` is core Signal code; it has no business
// acquiring a native-addon dependency just to remember a string pair.
//
// So the map lives here — no engine, no Signal imports, nothing to fail — and only the
// modules that genuinely need the engine import the engine.
//
// In memory only. It is rebuilt as messages are ingested or sent, and the demo backend
// is ephemeral anyway.

const messageIdByEh = new Map<string, string>();

// Note a persona post so its revocation flag can be kept current.
// What a persona post needs before it can be queued, once it is proved.
export type PreparedPersonaPost = {
  persona?: string;
  personaFlagged?: boolean;
  personaEh?: string;
  personaAnonymous?: boolean;
  personaRecordBase64?: string;
  personaBadge?: string;
  personaContextName?: string;
};

export function trackPersonaPost(eh: string, messageId: string): void {
  if (!eh || !messageId) {
    return;
  }
  messageIdByEh.set(eh, messageId);
}

// Every tracked (eh, messageId) pair, for the flag refresher to walk.
export function getTrackedPersonaPosts(): ReadonlyMap<string, string> {
  return messageIdByEh;
}

// --- the timestamp an own record is placed by ------------------------------------------
//
// Every replica must place a record on the SAME barrier, or replicas disagree about when
// a settlement happened, scans are rejected as stale, and members fork. Recipients place an
// anonymous record by the service timestamp, which a sender cannot choose.
//
// The sender does not know that timestamp yet when it applies its own record, so it places
// it provisionally at `stampOwnRecord`'s timestamp, which it also sends the Signal message
// with (enqueueMessageForSend reads it back with `takeOwnRecordSentAt`). The sender is one
// of the message's recipients, so the service delivers it a copy. That copy cannot be
// decrypted, but its envelope carries the service timestamp and this sent timestamp, and
// `settleOwnRecord` moves the record to where every other member placed it. Strictly
// increasing per process, so two records never share a Signal timestamp.
const ownRecordSentAt = new Map<string, number>();
let lastOwnSentAt = 0;

type OwnRecord = { groupId: string; recordBase64: string };

// Awaiting their copy from the service, by sent timestamp. Bounded: a record whose copy
// never comes stays where the sender placed it.
const MAX_UNSETTLED_RECORDS = 500;
const unsettledRecords = new Map<number, OwnRecord>();
let ownRecordSettler: (record: OwnRecord, serverMs: number) => void = () => undefined;

export function setOwnRecordSettler(
  settler: (record: OwnRecord, serverMs: number) => void
): void {
  ownRecordSettler = settler;
}

export function stampOwnRecord(groupId: string, recordBase64: string): number {
  const sentAt = Math.max(Date.now(), lastOwnSentAt + 1);
  lastOwnSentAt = sentAt;
  ownRecordSentAt.set(recordBase64, sentAt);
  unsettledRecords.set(sentAt, { groupId, recordBase64 });
  if (unsettledRecords.size > MAX_UNSETTLED_RECORDS) {
    const [oldest] = unsettledRecords.keys();
    if (oldest != null) {
      unsettledRecords.delete(oldest);
    }
  }
  return sentAt;
}

// The service delivered a copy of a phantom message we could not decrypt because we already
// used that chain step. If it is one of ours, this is the timestamp to place it by. Used
// once per record: a later message claiming the same sent timestamp changes nothing.
export function settleOwnRecord(sentAtMs: number, serverMs: number): void {
  const record = unsettledRecords.get(sentAtMs);
  if (record && serverMs > 0) {
    unsettledRecords.delete(sentAtMs);
    ownRecordSettler(record, serverMs);
  }
}

export function takeOwnRecordSentAt(recordBase64: string | undefined): number | undefined {
  if (!recordBase64) {
    return undefined;
  }
  const sentAt = ownRecordSentAt.get(recordBase64);
  ownRecordSentAt.delete(recordBase64);
  return sentAt;
}
