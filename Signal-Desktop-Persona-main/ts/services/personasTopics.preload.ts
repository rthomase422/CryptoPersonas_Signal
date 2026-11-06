// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — TOPIC CONTEXTS.
//
// A rate-limited persona is bound to a topic:
//
//     persona = H(sk || context || i),   i < MAX_PSEUDO
//
// so the same member has unlinkable petnames across topics, and at most MAX_PSEUDO
// identities within any one topic. The `context` is what makes that work, and every
// member of the group must agree on the same number for the same topic.
//
// The design calls for the CryptoPersonas server to draw that number at random, store
// it per thread, and hand it to clients. No such server exists in this architecture —
// the ZK engine runs client-side in each Desktop instance, and `deploy/` has only the
// Signal chat test-server and the storage-service. So the number is drawn CLIENT-side
// here and distributed over Signal itself:
//
//   1. the creator derives the context from the group and the name (contextForTopic),
//   2. broadcasts a topic ANNOUNCEMENT to the group (`PZT2:` carriage, hidden from the
//      timeline like the other protocol traffic),
//   3. every member ingests it into this registry.
//
// Sending it over Signal rather than through the roster dir is deliberate: the roster
// dir is a local directory, so it only works when every instance is on one machine.
// Announcements ride the group, so the demo works across machines.
//
// A topic announcement is NOT a ZK record. It carries no proof and the engine never
// sees it — it is pure coordination metadata, the stand-in for the server's registry.
// Everything funnels through `resolveTopicContext`, so pointing this at a real server
// endpoint later is a one-function change.
//
// KNOWN LIMIT: a member who joins after a topic was announced will not have it, since
// there is no backfill. Re-announcing on join, or a server registry, would fix it.

import type { ConversationModel } from '../models/conversations.preload.ts';
import {
  personasExtrasChanged,
  registerPersistedExtra,
} from './personasPersistence.preload.ts';

import { getPersonasEngine } from './personasEngine.preload.ts';
import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  encodeTopicAnnouncement,
  type PersonaTopicAnnouncement,
} from './personasCarriage.std.ts';
import { contextForTopic, topicNameInContext } from './personasTopicContext.std.ts';

const log = createLogger('personasTopics');

// Per personas group: name -> context. Rebuilt from announcements as they arrive.
const byGroup = new Map<string, Map<string, number>>();

function topicsOf(groupId: string): Map<string, number> {
  let topics = byGroup.get(groupId);
  if (!topics) {
    topics = new Map();
    byGroup.set(groupId, topics);
  }
  return topics;
}

// Saved with the member state (personasPersistence): a topic's context is announced once,
// so a restart would otherwise lose every topic (and its rate-limited personas).
registerPersistedExtra('topics', {
  snapshot: groupId => listTopics(groupId),
  restore: (groupId, value) => {
    if (!Array.isArray(value)) {
      return;
    }
    for (const topic of value) {
      if (
        typeof topic?.name === 'string' &&
        typeof topic?.context === 'number' &&
        Number.isSafeInteger(topic.context)
      ) {
        rememberTopic(groupId, { name: topic.name, context: topic.context });
      }
    }
  },
});

/**
 * The topic name a post may display: the one it claims, if the post's proof really is in
 * that topic's context. The name and the context are each bound to the post, but only
 * this ties them to each other.
 */
export function verifiedContextName(
  groupId: string | undefined,
  eh: string,
  contextName: string | undefined
): string | undefined {
  if (!groupId || !contextName) {
    return undefined;
  }
  return topicNameInContext(
    groupId,
    getPersonasEngine(groupId)?.postContext(eh),
    contextName
  );
}

/** Every topic this instance knows about in a group, for the composer's picker. */
export function listTopics(groupId: string): Array<{ name: string; context: number }> {
  return [...topicsOf(groupId).entries()]
    .map(([name, context]) => ({ name, context }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * The context for a named topic, or undefined if this instance has not heard of it.
 * THE seam: a server-backed registry would replace only this function (and
 * `createTopic`), leaving every caller untouched.
 */
// The reverse of resolveTopicContext: the human name for a context number, if this
// instance has heard its announcement. Used when SENDING, to label a post with the
// context it was made under so recipients can show it even before their own registry has
// caught up.
export function nameForContext(groupId: string, context: number): string | undefined {
  return listTopics(groupId).find(topic => topic.context === context)?.name;
}

export function resolveTopicContext(groupId: string, name: string): number | undefined {
  return topicsOf(groupId).get(name.trim());
}

/** Record a topic we learned about, from an announcement or from creating it. */
function rememberTopic(groupId: string, announcement: PersonaTopicAnnouncement): void {
  const name = announcement.name.trim();
  if (!name || announcement.context !== contextForTopic(groupId, name)) {
    return;
  }
  const contextByTopic = topicsOf(groupId);
  if (contextByTopic.has(name)) {
    return;
  }
  contextByTopic.set(name, announcement.context);
  personasExtrasChanged(groupId);
  log.info(`rememberTopic: "${name}" -> context ${announcement.context}`);
  // Surface it to the composer's picker. The renderer cannot import this module
  // (preload), so redux is the bridge.
  window.reduxActions?.composer?.personaTopicLearned(
    groupId,
    name,
    announcement.context
  );
}

/** Receive seam: fold an announcement that arrived over Signal in group `groupId`. */
export function ingestTopicAnnouncement(
  groupId: string,
  announcement: PersonaTopicAnnouncement
): void {
  rememberTopic(groupId, announcement);
}

/**
 * Create a topic: remember it and announce its name to the group, so every member can
 * offer it. Returns the context, or undefined on failure.
 *
 * Idempotent by name — creating an existing topic returns the known context and
 * re-announces it, which doubles as a crude backfill for members who missed it.
 */
export async function createTopic(
  conversation: ConversationModel,
  rawName: string
): Promise<number | undefined> {
  const name = rawName.trim();
  const groupId = conversation.get('groupId');
  if (!name || !groupId) {
    return undefined;
  }

  const context = contextForTopic(groupId, name);
  rememberTopic(groupId, { name, context });

  try {
    await conversation.enqueueMessageForSend(
      {
        body: encodeTopicAnnouncement({ name, context }),
        attachments: [],
      },
      // Coordination traffic, not chatter — never show the raw carriage string.
      { hideFromTimeline: true }
    );
    log.info(`createTopic: announced "${name}" -> ${context}`);
    return context;
  } catch (error) {
    log.error(`createTopic: announce failed: ${toLogFormat(error)}`);
    // Keep it locally anyway; a re-announce can follow.
    return context;
  }
}
