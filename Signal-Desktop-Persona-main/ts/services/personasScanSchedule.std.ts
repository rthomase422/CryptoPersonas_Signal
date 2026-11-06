// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// WHEN a member scans. A scan must not follow from anything the member just did, or its
// timing links their scans to their anonymous posts. So time is cut into public epochs on
// the group's shared schedule, and each member scans once per epoch at a moment drawn at
// random, whatever they are doing then. A scan never runs because a post is about to go
// out.
//
// Every member also sends the same number of scans per epoch, real ones first and dummy
// ones to make up the count, so the number says nothing about a member's tickets. A
// member with more tickets than the count still finishes its sweep, because posting waits
// for that, so the count should cover a typical sweep.

const DEFAULT_SCAN_EPOCH_MS = 24 * 60 * 60 * 1_000;
const DEFAULT_SCANS_PER_EPOCH = 36;

// The epoch length: a day, or PERSONAS_SCAN_EPOCH_MS for a demo. A ban or badge reaches
// an honest member's object at its next slot, so this is also how long that can take.
export function scanEpochMs(override?: string): number {
  const parsed = Number(override);
  return parsed > 0 ? parsed : DEFAULT_SCAN_EPOCH_MS;
}

// Scans per member per epoch: PERSONAS_SCANS_PER_EPOCH, or enough for a sweep of the
// tickets a busy member holds over the ban window.
export function scansPerEpoch(override?: string): number {
  const parsed = Number(override);
  return Number.isInteger(parsed) && parsed > 0
    ? parsed
    : DEFAULT_SCANS_PER_EPOCH;
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
