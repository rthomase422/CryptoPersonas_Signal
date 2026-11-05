// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// WHEN a member scans. A scan must not follow from anything the member just did, or its
// timing links their scans to their anonymous posts. So time is cut into public epochs on
// the group's shared schedule, and each member scans once per epoch at a moment drawn at
// random, whatever they are doing then. A scan never runs because a post is about to go
// out.
//
// How MANY scans a member sends in its slot still depends on its tickets until dummy
// scans exist, which needs a circuit change. Scans carry no sender, so that count says
// nothing about who scanned.

const DEFAULT_SCAN_EPOCH_MS = 60 * 60 * 1_000;

// The epoch length: an hour, or PERSONAS_SCAN_EPOCH_MS for a demo. A ban or badge reaches
// a member's object at its next slot, so this is also how long that can take.
export function scanEpochMs(override?: string): number {
  const parsed = Number(override);
  return parsed > 0 ? parsed : DEFAULT_SCAN_EPOCH_MS;
}

export function scanEpochAt(
  nowMs: number,
  anchorMs: number,
  epochMs: number
): number {
  return Math.floor((nowMs - anchorMs) / epochMs);
}

// A random moment between `nowMs` and the end of the epoch `nowMs` is in, for `random` in
// [0, 1). Starting from now, not the start of the epoch, so that a client that opens
// partway through still scans in this epoch.
export function pickScanSlot(
  nowMs: number,
  anchorMs: number,
  epochMs: number,
  random: number
): number {
  const epochEnd =
    anchorMs + (scanEpochAt(nowMs, anchorMs, epochMs) + 1) * epochMs;
  return nowMs + Math.floor(random * (epochEnd - nowMs));
}
