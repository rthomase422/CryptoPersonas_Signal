// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { assert } from 'chai';

import {
  pickScanSlot,
  scanEpochAt,
  scanEpochMs,
  scansPerEpoch,
} from '../../services/personasScanSchedule.std.ts';

const HOUR = 3_600_000;
const ANCHOR = 1_000_000;

describe('personasScanSchedule', () => {
  it('uses a day unless told otherwise', () => {
    assert.equal(scanEpochMs(undefined), 24 * HOUR);
    assert.equal(scanEpochMs(''), 24 * HOUR);
    assert.equal(scanEpochMs('nonsense'), 24 * HOUR);
    assert.equal(scanEpochMs('0'), 24 * HOUR);
    assert.equal(scanEpochMs('60000'), 60_000);
  });

  it('sends a fixed number of scans unless told otherwise', () => {
    assert.equal(scansPerEpoch(undefined), 36);
    assert.equal(scansPerEpoch('1.5'), 36);
    assert.equal(scansPerEpoch('4'), 4);
  });

  it('numbers epochs from the anchor, so members agree on them', () => {
    assert.equal(scanEpochAt(ANCHOR, ANCHOR, HOUR), 0);
    assert.equal(scanEpochAt(ANCHOR + HOUR - 1, ANCHOR, HOUR), 0);
    assert.equal(scanEpochAt(ANCHOR + HOUR, ANCHOR, HOUR), 1);
  });

  it('keeps a slot inside the epoch it was drawn in', () => {
    const now = ANCHOR + 3 * HOUR + 1_234;
    for (const random of [0, 0.25, 0.5, 0.999999]) {
      const slot = pickScanSlot(now, ANCHOR, HOUR, random);
      assert.isAtLeast(slot, now);
      assert.equal(scanEpochAt(slot, ANCHOR, HOUR), 3);
    }
  });
});
