// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — the SHARED BARRIER SCHEDULE, one per personas group.
//
// A replica only crosses a settlement barrier when told to. Across N Desktop instances
// that has to happen at the same points in the record stream, or replica roots diverge;
// and it has to happen on time even in a silent group, or a ban poll never settles.
//
// The engine already has the fix: construct it with `heartbeatAnchorMs` +
// `heartbeatPeriodMs` and every replica buckets an ingest onto a barrier derived from a
// timestamp every recipient sees identically, instead of local arrival order.
// `tick(nowMs)` then advances to the barrier the same schedule says wall-clock has
// reached.
//
// Each group's schedule is fixed by its PHANTOM BUNDLE: the member who minted the bundle
// picked it, and every member that holds the bundle agrees on it with nothing shared but
// the bundle itself. A group with no bundle has no engine, and so no schedule.

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { getPhantomSchedule } from './personasPhantom.preload.ts';

const log = createLogger('personasBarrier');

// How often we nudge each replica forward. Must be well under the period so a barrier is
// crossed promptly once wall-clock passes it.
const TICK_INTERVAL_MS = 1_000;

export type BarrierSchedule = {
  anchorMs: number;
  periodMs: number;
};

// The schedule `groupId`'s members share, or undefined when we hold no bundle for it.
export function getBarrierSchedule(groupId: string | undefined): BarrierSchedule | undefined {
  const fromBundle = getPhantomSchedule(groupId);
  return fromBundle
    ? { anchorMs: fromBundle.anchorMs, periodMs: fromBundle.periodMs }
    : undefined;
}

// The timestamp a RECEIVED record is placed by. An anonymous record goes by the service
// timestamp, which its sender cannot choose, so no member can place its own record on a
// barrier of its choice. Every recipient of one multi-recipient send sees the same value.
//
// An attributable record (a join, a re-join approval, an admin ban) is not echoed to its
// sender, so it goes by the sender's own sent timestamp, unless that is implausibly far
// from the service's. Every recipient sees the same two values, so they agree either way.
//
// A sender's skew bounds how many barriers it can choose between: about three at a period
// of 10 s.
const MAX_SENT_AT_SKEW_MS = 10_000;
export function recordTimestamp(
  sentAtMs: number | null | undefined,
  serverTimestampMs: number | null | undefined,
  attributable: boolean
): number {
  if (!attributable && serverTimestampMs != null && serverTimestampMs > 0) {
    return serverTimestampMs;
  }
  if (sentAtMs != null && sentAtMs > 0) {
    if (
      serverTimestampMs == null ||
      serverTimestampMs <= 0 ||
      Math.abs(sentAtMs - serverTimestampMs) <= MAX_SENT_AT_SKEW_MS
    ) {
      return sentAtMs;
    }
  }
  return serverTimestampMs ?? 0;
}

// The timestamp to hand a group's `Engine.ingest` for a record: the record's timestamp
// on the shared schedule (local wall-clock if it has none, e.g. our own just-emitted
// record), or `0` — the local-barrier cadence — with no schedule.
export function ingestTimestampFor(
  groupId: string | undefined,
  timestampMs?: number | null
): number {
  if (!getBarrierSchedule(groupId)) {
    return 0;
  }
  if (timestampMs != null && timestampMs > 0) {
    return timestampMs;
  }
  return Date.now();
}

const tickers = new Map<string, { interval: NodeJS.Timeout; lastBarrier: number }>();

// Start nudging a group's replica along its schedule. Without this a barrier is only
// crossed when a record happens to arrive in a later bucket, so a ban poll in a quiet
// group would never settle. `advance` is idempotent per barrier: it advances TO the
// barrier the schedule says `nowMs` reached and returns it.
export function startBarrierTicker(
  groupId: string,
  advance: (nowMs: number) => number | undefined
): void {
  if (tickers.has(groupId) || !getBarrierSchedule(groupId)) {
    return;
  }
  log.info(`startBarrierTicker: ticking every ${TICK_INTERVAL_MS}ms`);
  const ticker = {
    lastBarrier: -1,
    interval: setInterval(() => {
      try {
        const barrier = advance(Date.now());
        if (barrier != null && barrier !== ticker.lastBarrier) {
          ticker.lastBarrier = barrier;
          log.info(`startBarrierTicker: crossed to barrier ${barrier}`);
        }
      } catch (error) {
        log.error(`startBarrierTicker: tick failed: ${toLogFormat(error)}`);
      }
    }, TICK_INTERVAL_MS),
  };
  tickers.set(groupId, ticker);
}
