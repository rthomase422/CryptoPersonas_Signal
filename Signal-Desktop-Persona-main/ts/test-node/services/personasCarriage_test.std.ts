// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: tests for the carriage convention — the pure, engine-free layer that
// decides how a CryptoPersonas record is packed into a message body and, crucially,
// how the SEND path tells a post apart from everything else.
//
// This is the one piece of the persona stack that is worth unit-testing in isolation,
// and it is worth it because a mistake here is a silent de-anonymisation rather than a
// crash: `isPersonaPhantomBody` is what routes a message onto the shared phantom
// identity. If it ever returned false for a real post, poll or ballot, that record
// would go out attributably under the author's own account and nothing would look
// broken.
//
// (The engine itself is a native darwin-arm64 addon with a ~51MB proving-key bundle;
// its own convergence/ban behaviour is covered by packages/personas-engine/test/
// converge.mjs, which needs that binary.)

import { assert } from 'chai';

import {
  PERSONAS_MARKER,
  PERSONAS_POST_MARKER,
  PERSONAS_POLL_MARKER,
  PERSONAS_VOTE_MARKER,
  PERSONAS_RATE_MARKER,
  PERSONAS_SCAN_MARKER,
  PERSONAS_TOPIC_MARKER,
  PERSONAS_BADGE_MARKER,
  PERSONAS_BADGE_PROOF_MARKER,
  encodeRecordBody,
  encodeBadgeBody,
  encodePostBody,
  encodePollBody,
  decodeRecordBody,
  pollDescriptorFromRecord,
  encodeVoteBody,
  encodeRateBody,
  encodeScanBody,
  encodeTopicAnnouncement,
  decodeTopicAnnouncement,
  isPersonaPhantomBody,
  PERSONAS_RELAY_MARKER,
  encodeRelayBody,
  decodeRelayBody,
  encodeResetRequest,
  decodeResetRequest,
  encodeCatchUpRequest,
  isCatchUpRequest,
  encodeCatchUpParts,
  decodeCatchUpPart,
  CATCH_UP_PART_DATA_CHARS,
  PERSONAS_CATCH_UP_PART_MARKER,
  PERSONAS_RESET_REQUEST_MARKER,
  encodeAuthorshipProof,
  decodeAuthorshipProof,
  encodeBadgeProof,
  decodeBadgeProof,
  PERSONAS_AUTHORSHIP_MARKER,
  decodePostBadge,
  decodePostContextName,
  PERSONAS_PHANTOM_BUNDLE_MARKER,
  encodePhantomBundle,
  decodePhantomBundle,
  type PersonaPhantomBundleWire,
} from '../../services/personasCarriage.std.ts';

const RECORD = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f]);

describe('personasCarriage', () => {
  describe('round trips', () => {
    it('recovers the record bytes from an attributable body', () => {
      const body = encodeRecordBody(RECORD);
      assert.isTrue(body.startsWith(PERSONAS_MARKER));
      assert.deepEqual(decodeRecordBody(body), RECORD);
    });

    it('recovers the record bytes from a post body', () => {
      const body = encodePostBody(RECORD);
      assert.isTrue(body.startsWith(PERSONAS_POST_MARKER));
      assert.deepEqual(decodeRecordBody(body), RECORD);
    });

    it('recovers the record bytes from a poll body', () => {
      const body = encodePollBody(RECORD);
      assert.isTrue(body.startsWith(PERSONAS_POLL_MARKER));
      assert.deepEqual(decodeRecordBody(body), RECORD);
    });

    it('recovers the record bytes from a scan body', () => {
      const body = encodeScanBody(RECORD);
      assert.isTrue(body.startsWith(PERSONAS_SCAN_MARKER));
      assert.deepEqual(decodeRecordBody(body), RECORD);
    });
  });

  describe('pollDescriptorFromRecord', () => {
    it('keeps a standard poll as written', () => {
      assert.deepEqual(
        pollDescriptorFromRecord({
          question: 'Lunch?',
          options: ['Pizza', 'Tacos', 'Soup'],
          kind: 'standard',
        }),
        {
          question: 'Lunch?',
          options: ['Pizza', 'Tacos', 'Soup'],
          kind: 'standard',
        }
      );
    });

    it('cannot disguise a ban poll', () => {
      const shown = pollDescriptorFromRecord({
        question: 'Lunch at noon?',
        options: ['Yes', 'No'],
        kind: 'ban',
      });
      assert.equal(shown.kind, 'ban');
      assert.notInclude(shown.question, 'Lunch');
      assert.deepEqual(shown.options, ['Ban', 'Keep']);
    });
  });

  describe('decodeRecordBody', () => {
    it('returns undefined for ordinary chatter', () => {
      assert.isUndefined(decodeRecordBody('hello there'));
      assert.isUndefined(decodeRecordBody(''));
      assert.isUndefined(decodeRecordBody(undefined));
      assert.isUndefined(decodeRecordBody(null));
    });

    it('does not treat a marker appearing mid-body as a record', () => {
      assert.isUndefined(decodeRecordBody(`look at this ${PERSONAS_MARKER}abc`));
    });

  });

  describe('isPersonaPhantomBody', () => {
    // This is the phantom-routing gate. Getting it wrong in either direction is a
    // correctness bug with privacy consequences, so both directions are asserted.
    const poll = () => encodePollBody(RECORD);

    it('is true for the records whose author must be unlinkable', () => {
      // Posts, polls and ballots: an attributable poll would expose who called for a
      // revocation, and an attributable ballot would defeat an anonymous poll.
      assert.isTrue(isPersonaPhantomBody(encodePostBody(RECORD)));
      assert.isTrue(isPersonaPhantomBody(poll()));
      assert.isTrue(isPersonaPhantomBody(encodeVoteBody(RECORD)));
      // A rating is pseudonymous in-circuit too (context = target.context()), so an
      // attributable envelope would name the rater outright.
      assert.isTrue(isPersonaPhantomBody(encodeRateBody(RECORD)));
      // A scan: when and how often a member scans follows their private tickets, so a
      // named scan would point at their anonymous posts.
      assert.isTrue(isPersonaPhantomBody(encodeScanBody(RECORD)));
      // A badge request/approval: the grant travels by callback, so the sender's
      // identity is unused by the protocol and must not be published by the envelope.
      assert.isTrue(isPersonaPhantomBody(encodeBadgeBody(RECORD)));
      // An AUTHORSHIP PROOF. This one is the easiest to get wrong and the most
      // damaging: the proof's entire purpose is to link two pseudonyms WITHOUT naming
      // their author, so an attributable envelope does not merely leak a little — it
      // answers the exact question the proof refuses to answer, making it pointless.
      assert.isTrue(isPersonaPhantomBody(encodeAuthorshipProof(RECORD)));
      // A BADGE POSSESSION PROOF. The claim is "someone here holds Faculty", and the
      // envelope naming that someone would collapse it to "this person holds Faculty".
      assert.isTrue(isPersonaPhantomBody(encodeBadgeProof(RECORD)));
    });

    it('is false for attributable records and plain chatter', () => {
      // Joins stay attributable: one membership per real account is what makes a ban
      // impossible to evade by re-joining.
      assert.isFalse(isPersonaPhantomBody(encodeRecordBody(RECORD)));
      assert.isFalse(isPersonaPhantomBody('just a message'));
      assert.isFalse(isPersonaPhantomBody(undefined));
      assert.isFalse(isPersonaPhantomBody(null));
    });
  });

  describe('badge records', () => {
    it('round trips under its own marker', () => {
      const body = encodeBadgeBody(RECORD);
      assert.isTrue(body.startsWith(PERSONAS_BADGE_MARKER));
      assert.deepEqual(decodeRecordBody(body), RECORD);
    });

    it('is a ZK record, unlike an authorship proof or a topic announcement', () => {
      // A badge request/approval DOES go to `ingest` — it is a bulletin record that
      // files or settles a callback. An authorship proof does not. Conflating the two
      // would either hand the engine something it rejects or skip ingesting a record
      // the replica needs, and both failures are quiet.
      assert.isDefined(decodeRecordBody(encodeBadgeBody(RECORD)));
      assert.isUndefined(decodeRecordBody(encodeAuthorshipProof(RECORD)));
    });

    it('is not confused with an attributable join', () => {
      // The ONLY difference between these two bodies is the marker, and the marker is
      // what decides whether the sender is named. Same payload, opposite routing.
      const join = encodeRecordBody(RECORD);
      const badge = encodeBadgeBody(RECORD);
      assert.notEqual(join, badge);
      assert.deepEqual(decodeRecordBody(join), decodeRecordBody(badge));
      assert.isFalse(isPersonaPhantomBody(join));
      assert.isTrue(isPersonaPhantomBody(badge));
    });
  });

  describe('topic announcements', () => {
    it('round trips a name and context', () => {
      const announcement = { name: 'Union', context: 123456789 };
      const body = encodeTopicAnnouncement(announcement);
      assert.isTrue(body.startsWith(PERSONAS_TOPIC_MARKER));
      assert.deepEqual(decodeTopicAnnouncement(body), announcement);
    });

    it('is not mistaken for a ZK record', () => {
      // An announcement carries no proof; handing it to the engine would be rejected,
      // so decodeRecordBody must not claim it.
      const body = encodeTopicAnnouncement({ name: 'Union', context: 7 });
      assert.isUndefined(decodeRecordBody(body));
      assert.isFalse(isPersonaPhantomBody(body));
    });

    it('returns undefined for other bodies', () => {
      assert.isUndefined(decodeTopicAnnouncement(encodePostBody(RECORD)));
      assert.isUndefined(decodeTopicAnnouncement('hello'));
      assert.isUndefined(decodeTopicAnnouncement(undefined));
    });
  });

  describe('marker distinctness', () => {
    it('uses nine distinct, equal-length markers', () => {
      const markers = [
        PERSONAS_MARKER,
        PERSONAS_POST_MARKER,
        PERSONAS_POLL_MARKER,
        PERSONAS_VOTE_MARKER,
        PERSONAS_RATE_MARKER,
        PERSONAS_TOPIC_MARKER,
        PERSONAS_BADGE_MARKER,
        PERSONAS_AUTHORSHIP_MARKER,
        PERSONAS_BADGE_PROOF_MARKER,
      ];
      assert.equal(new Set(markers).size, 9);
      // Equal length keeps the `body.slice(marker.length)` decode uniform, and means
      // no marker can be a prefix of another.
      assert.equal(new Set(markers.map(m => m.length)).size, 1);
    });
  });
});

describe('post badge claims', () => {
  const record = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x7b, 0x22]);

  it('encodes a plain post exactly as before badges existed', () => {
    // Backward compatibility is the whole point of the two-shape design: an instance
    // that never sets a badge must produce byte-identical bodies to the old build.
    assert.strictEqual(
      encodePostBody(record),
      `PZP2:${record.toString('base64')}`
    );
  });

  it('round-trips the record through a badged post', () => {
    const body = encodePostBody(record, 'Faculty');
    assert.deepStrictEqual(decodeRecordBody(body), record);
    assert.strictEqual(decodePostBadge(body), 'Faculty');
  });

  it('round-trips the record through a plain post', () => {
    const body = encodePostBody(record);
    assert.deepStrictEqual(decodeRecordBody(body), record);
    assert.strictEqual(decodePostBadge(body), undefined);
  });

  it('still routes a badged post over the phantom identity', () => {
    // A badge must not change the anonymity routing: a badged post is still a post.
    assert.ok(isPersonaPhantomBody(encodePostBody(record, 'Student')));
  });

  it('treats a malformed envelope as a plain post rather than throwing', () => {
    const body = `PZP2:${Buffer.from('{"nope":1}', 'utf8').toString('base64')}`;
    assert.strictEqual(decodePostBadge(body), undefined);
    assert.doesNotThrow(() => decodeRecordBody(body));
  });

  it('ignores a non-string badge from a hostile peer', () => {
    const envelope = JSON.stringify({ r: record.toString('base64'), b: 42 });
    const body = `PZP2:${Buffer.from(envelope, 'utf8').toString('base64')}`;
    assert.strictEqual(decodePostBadge(body), undefined);
    assert.deepStrictEqual(decodeRecordBody(body), record);
  });
});

describe('post context names', () => {
  const record = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x7b, 0x22, 0x00]);

  it('keeps a plain post byte-identical to the pre-context format', () => {
    assert.strictEqual(
      encodePostBody(record),
      `PZP2:${record.toString('base64')}`
    );
  });

  it('round-trips a context-only post', () => {
    const body = encodePostBody(record, undefined, 'Union');
    assert.deepStrictEqual(decodeRecordBody(body), record);
    assert.strictEqual(decodePostContextName(body), 'Union');
    assert.strictEqual(decodePostBadge(body), undefined);
  });

  it('round-trips a badge AND a context together', () => {
    const body = encodePostBody(record, 'Faculty', 'Union');
    assert.deepStrictEqual(decodeRecordBody(body), record);
    assert.strictEqual(decodePostBadge(body), 'Faculty');
    assert.strictEqual(decodePostContextName(body), 'Union');
  });

  it('ignores a non-string context from a hostile peer', () => {
    const envelope = JSON.stringify({ r: record.toString('base64'), c: 42 });
    const body = `PZP2:${Buffer.from(envelope, 'utf8').toString('base64')}`;
    assert.strictEqual(decodePostContextName(body), undefined);
    assert.deepStrictEqual(decodeRecordBody(body), record);
  });

  it('still routes a context-labelled post over the phantom', () => {
    assert.ok(isPersonaPhantomBody(encodePostBody(record, undefined, 'Union')));
  });
});

describe('authorship proof carriage', () => {
  const PROOF = Buffer.from([0, 1, 2, 250, 251, 252, 253, 254, 255]);

  it('round-trips the proof bytes exactly', () => {
    const body = encodeAuthorshipProof(PROOF);
    const back = decodeAuthorshipProof(body);
    assert.isDefined(back);
    // Byte-exact: a Groth16 proof that loses or gains a byte does not verify, and the
    // failure would surface as "proof invalid" rather than "carriage is wrong".
    assert.deepEqual(Array.from(back as Buffer), Array.from(PROOF));
  });

  it('uses the authorship marker', () => {
    assert.isTrue(
      encodeAuthorshipProof(PROOF).startsWith(PERSONAS_AUTHORSHIP_MARKER)
    );
  });

  it('carries NO names', () => {
    // The security property: names are derived from the proof's public inputs, so a
    // name must never travel on the wire where a recipient could render it instead.
    const body = encodeAuthorshipProof(PROOF);
    assert.notInclude(body.toLowerCase(), 'first');
    assert.notInclude(body.toLowerCase(), 'second');
  });

  it('DOES ride the shared phantom', () => {
    // Reversed deliberately, and this test's history is the argument for the change.
    //
    // It used to assert the opposite, on the reasoning that "the claimant is saying
    // something about their OWN personas". That held while authorship was an
    // unverified typed claim. It stopped holding the moment it became a proof: the
    // proof establishes that two pseudonyms share an author while revealing nothing
    // about WHO, so an attributable envelope answers — for free, to everyone — the one
    // question the proof is constructed to leave open.
    //
    // A green test asserting the old behaviour is worse than no test, because it
    // presents a leak as an invariant.
    assert.isTrue(isPersonaPhantomBody(encodeAuthorshipProof(PROOF)));
  });

  it('returns undefined for a non-authorship body', () => {
    assert.isUndefined(decodeAuthorshipProof('just a message'));
    assert.isUndefined(decodeAuthorshipProof(undefined));
    assert.isUndefined(decodeAuthorshipProof(null));
  });
});

describe('badge possession proof carriage', () => {
  const PROOF = Buffer.from([9, 8, 7, 0, 255, 128, 1]);

  it('round-trips the proof bytes exactly', () => {
    // Byte-exact, for the same reason authorship is: a Groth16 proof that loses or
    // gains a byte does not verify, and the symptom would read as "proof invalid"
    // rather than "carriage is wrong".
    const back = decodeBadgeProof(encodeBadgeProof(PROOF));
    assert.isDefined(back);
    assert.deepEqual(Array.from(back as Buffer), Array.from(PROOF));
  });

  it('uses its own marker, distinct from the badge RECORD marker', () => {
    // PZG2 (proof) vs PZB2 (request/approval record). Confusing them would either hand
    // the engine a proof to `ingest` — which it would reject — or skip ingesting a
    // record the replica needs. Both failures are quiet.
    assert.isTrue(
      encodeBadgeProof(PROOF).startsWith(PERSONAS_BADGE_PROOF_MARKER)
    );
    assert.notEqual(PERSONAS_BADGE_PROOF_MARKER, PERSONAS_BADGE_MARKER);
    assert.isUndefined(decodeBadgeProof(encodeBadgeBody(PROOF)));
    assert.isUndefined(decodeRecordBody(encodeBadgeProof(PROOF)));
  });

  it('carries NO badge name', () => {
    // The security property. The name is an OUTPUT of verification; if it travelled
    // alongside the proof, a valid Industry proof could be rendered as Faculty and the
    // verified checkmark would be true while the statement was false.
    const body = encodeBadgeProof(PROOF);
    for (const name of ['faculty', 'student', 'industry', 'badge']) {
      assert.notInclude(body.toLowerCase().slice(5), name);
    }
  });

  it('is not confused with an authorship proof', () => {
    assert.isUndefined(decodeBadgeProof(encodeAuthorshipProof(PROOF)));
    assert.isUndefined(decodeAuthorshipProof(encodeBadgeProof(PROOF)));
  });

  it('returns undefined for a non-proof body', () => {
    assert.isUndefined(decodeBadgeProof('just a message'));
    assert.isUndefined(decodeBadgeProof(undefined));
    assert.isUndefined(decodeBadgeProof(null));
  });
});

describe('personasCarriage phantom bundle', () => {
  const bundle: PersonaPhantomBundleWire = {
    v: 2,
    groupId: 'Z3JvdXAtaWQ=',
    trustRootPublic: 'dHJ1c3Q=',
    phantomIdentityKeyPair: 'aWQ=',
    phantomCert: 'Y2VydA==',
    distributionId: '9f9f9f9f-0000-4000-8000-0000000d15c0',
    skdm: 'c2tkbQ==',
    chainRecord: 'Y2hhaW4=',
    schedule: { anchorMs: 1_790_000_000_000, periodMs: 10_000 },
  };

  it('round-trips through its own marker', () => {
    const body = encodePhantomBundle(bundle);
    assert.isTrue(body.startsWith(PERSONAS_PHANTOM_BUNDLE_MARKER));
    assert.deepEqual(decodePhantomBundle(body), bundle);
  });

  it('is never routed through the phantom (it is sent 1:1, attributably)', () => {
    assert.isFalse(isPersonaPhantomBody(encodePhantomBundle(bundle)));
  });

  it('is not mistaken for a ZK record or a topic announcement', () => {
    const body = encodePhantomBundle(bundle);
    assert.isUndefined(decodeRecordBody(body));
    assert.isUndefined(decodeTopicAnnouncement(body));
  });

  it('rejects a bundle with a missing field, a bad schedule, or another version', () => {
    const encode = (value: unknown) =>
      PERSONAS_PHANTOM_BUNDLE_MARKER +
      Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
    assert.isUndefined(decodePhantomBundle(encode({ ...bundle, chainRecord: '' })));
    assert.isUndefined(
      decodePhantomBundle(encode({ ...bundle, schedule: { anchorMs: 1, periodMs: 0 } }))
    );
    assert.isUndefined(decodePhantomBundle(encode({ ...bundle, v: 1 })));
    // A bundle must name its group: version 1 bundles were shared across groups.
    assert.isUndefined(decodePhantomBundle(encode({ ...bundle, groupId: '' })));
    const { groupId: _groupId, ...noGroup } = bundle;
    assert.isUndefined(decodePhantomBundle(encode({ ...noGroup, v: 2 })));
    assert.isUndefined(decodePhantomBundle(`${PERSONAS_PHANTOM_BUNDLE_MARKER}not base64 json`));
    assert.isUndefined(decodePhantomBundle('just a message'));
    assert.isUndefined(decodePhantomBundle(undefined));
  });
});

describe('personas reset request carriage', () => {
  const account = '0123456789abcdef0123456789abcdef';

  it('round-trips a request with and without a proof', () => {
    const withProof = { a: account, p: 'cHJvb2Y=' };
    assert.deepEqual(decodeResetRequest(encodeResetRequest(withProof)), withProof);
    const without = { a: account, p: null, r: 'a full scan is needed first' };
    assert.deepEqual(decodeResetRequest(encodeResetRequest(without)), without);
  });

  it('refuses malformed requests', () => {
    assert.isUndefined(decodeResetRequest('hello'));
    assert.isUndefined(decodeResetRequest(`${PERSONAS_RESET_REQUEST_MARKER}not base64 json`));
    assert.isUndefined(decodeResetRequest(encodeResetRequest({ a: 'not-an-account', p: null })));
    assert.isUndefined(
      decodeResetRequest(
        PERSONAS_RESET_REQUEST_MARKER +
          Buffer.from(JSON.stringify({ a: account, p: 42 })).toString('base64')
      )
    );
  });

  it('is never routed through the anonymous phantom', () => {
    assert.isFalse(isPersonaPhantomBody(encodeResetRequest({ a: account, p: null })));
  });
});

describe('personas catch-up carriage', () => {
  it('recognises a request', () => {
    assert.isTrue(isCatchUpRequest(encodeCatchUpRequest()));
    assert.isFalse(isCatchUpRequest('hello'));
    assert.isFalse(isCatchUpRequest(undefined));
  });

  it('splits a history into parts that each fit inline, and reassembles it', () => {
    const history = Buffer.alloc(5000);
    for (let i = 0; i < history.length; i += 1) {
      history[i] = (i * 31) % 256;
    }
    const parts = encodeCatchUpParts('group-id', 'copy-1', history);
    assert.isAbove(parts.length, 1);
    for (const part of parts) {
      assert.isAtMost(Buffer.byteLength(part), 2048);
    }
    const decoded = parts.map(p => decodeCatchUpPart(p));
    decoded.forEach((d, i) => {
      assert.equal(d?.i, i);
      assert.equal(d?.n, parts.length);
      assert.equal(d?.g, 'group-id');
      assert.equal(d?.s, 'copy-1');
    });
    const joined = Buffer.from(decoded.map(d => d?.d ?? '').join(''), 'base64');
    assert.isTrue(joined.equals(history));
    assert.isAtMost(decoded[0]?.d.length ?? 0, CATCH_UP_PART_DATA_CHARS);
  });

  it('refuses malformed parts', () => {
    const bad = (wire: unknown) =>
      PERSONAS_CATCH_UP_PART_MARKER +
      Buffer.from(JSON.stringify(wire)).toString('base64');
    assert.isUndefined(decodeCatchUpPart('hello'));
    assert.isUndefined(decodeCatchUpPart(bad({ g: 'g', s: 's', i: 2, n: 2, d: '' })));
    assert.isUndefined(decodeCatchUpPart(bad({ g: 'g', s: 's', i: 0, n: 0, d: '' })));
    assert.isUndefined(decodeCatchUpPart(bad({ g: 1, s: 's', i: 0, n: 1, d: '' })));
  });
});

describe('personas relay carriage', () => {
  const record = Buffer.from([1, 2, 3, 250]);

  it('round-trips a record with its barrier', () => {
    const body = encodeRelayBody(42, record);
    assert.isTrue(body.startsWith(PERSONAS_RELAY_MARKER));
    const relay = decodeRelayBody(body);
    assert.equal(relay?.barrier, 42);
    assert.isTrue(relay?.record.equals(record));
  });

  it('matches the Rust carriage byte for byte', () => {
    // carriage.rs: format!("{RELAY_MARKER}{first_barrier}:{}", B64.encode(record))
    assert.equal(encodeRelayBody(7, record), 'PZY2:7:AQID+g==');
  });

  it('is not a plain record, and does not ride the phantom', () => {
    const body = encodeRelayBody(1, record);
    assert.isUndefined(decodeRecordBody(body));
    assert.isFalse(isPersonaPhantomBody(body));
  });

  it('refuses malformed relays', () => {
    assert.isUndefined(decodeRelayBody('hello'));
    assert.isUndefined(decodeRelayBody(`${PERSONAS_RELAY_MARKER}AQID`));
    assert.isUndefined(decodeRelayBody(`${PERSONAS_RELAY_MARKER}-1:AQID`));
    assert.isUndefined(decodeRelayBody(`${PERSONAS_RELAY_MARKER}x:AQID`));
    assert.isUndefined(decodeRelayBody(`${PERSONAS_RELAY_MARKER}3:`));
  });
});
