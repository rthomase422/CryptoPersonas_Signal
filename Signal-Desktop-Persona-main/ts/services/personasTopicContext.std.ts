// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — how a topic's name and its context relate.

import { createHash } from 'node:crypto';

// Contexts are hashed inside the circuit as a field element. Stay well inside the
// exact-integer range of a JS number (2^53) so the value survives JSON and the napi
// boundary unchanged — a context that differs by one bit between members produces a
// different persona and silently breaks linkability within the topic.
const CONTEXT_BYTES = 6; // 48 bits

// A topic's context is a hash of its name, so a name has exactly one context. If members
// could pick the number, anyone could mint fresh contexts that display under an existing
// topic's name, and get a fresh allowance of rate-limited personas in it each time.
export function contextForTopic(groupId: string, rawName: string): number {
  const bytes = createHash('sha256')
    .update(`${groupId}\u0000${rawName.trim().toLowerCase()}`)
    .digest()
    .subarray(0, CONTEXT_BYTES);
  let value = 0;
  for (const byte of bytes) {
    value = value * 256 + byte;
  }
  // Never 0 — that is the "no topic" sentinel used by the unlimited plain pseudonym.
  return value === 0 ? 1 : value;
}

/** `name`, if a post proved in `context` may display it. */
export function topicNameInContext(
  groupId: string,
  context: number | null | undefined,
  name: string
): string | undefined {
  return context === contextForTopic(groupId, name) ? name : undefined;
}
