// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { assert } from 'chai';

import {
  setOwnRecordSettler,
  settleOwnRecord,
  stampOwnRecord,
} from '../../services/personasRegistry.std.ts';

describe('personasRegistry own records', () => {
  it('places a record once, when its copy comes back', () => {
    const settled: Array<[string, string, number]> = [];
    setOwnRecordSettler(({ groupId, recordBase64 }, serverMs) => {
      settled.push([groupId, recordBase64, serverMs]);
    });
    const sentAt = stampOwnRecord('group', 'record');

    settleOwnRecord(sentAt, 12_345);
    settleOwnRecord(sentAt, 99_999);

    assert.deepEqual(settled, [['group', 'record', 12_345]]);
  });

  it('ignores a copy of something we did not send', () => {
    let called = false;
    setOwnRecordSettler(() => {
      called = true;
    });
    settleOwnRecord(1, 12_345);
    assert.isFalse(called);
  });
});
