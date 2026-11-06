// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { assert } from 'chai';

import {
  contextForTopic,
  topicNameInContext,
} from '../../services/personasTopicContext.std.ts';

describe('personas topic contexts', () => {
  it('gives one topic name one context', () => {
    const context = contextForTopic('group', 'Housing');

    assert.strictEqual(contextForTopic('group', 'Housing'), context);
    assert.strictEqual(contextForTopic('group', '  hOUSING '), context);
  });

  it('gives different names and different groups different contexts', () => {
    const context = contextForTopic('group', 'Housing');

    assert.notStrictEqual(contextForTopic('group', 'Parking'), context);
    assert.notStrictEqual(contextForTopic('other group', 'Housing'), context);
  });

  it('stays an exact integer and never the no-topic value', () => {
    const context = contextForTopic('group', 'Housing');

    assert.isTrue(Number.isSafeInteger(context));
    assert.isAbove(context, 0);
  });

  it('shows a topic name on a post proved in that topic', () => {
    const context = contextForTopic('group', 'Housing');

    assert.strictEqual(topicNameInContext('group', context, 'Housing'), 'Housing');
  });

  it('refuses a topic name from a different context', () => {
    const other = contextForTopic('group', 'Parking');

    assert.isUndefined(topicNameInContext('group', other, 'Housing'));
  });

  it('refuses a topic name on a post with no context', () => {
    assert.isUndefined(topicNameInContext('group', undefined, 'Housing'));
    assert.isUndefined(topicNameInContext('group', null, 'Housing'));
  });
});
