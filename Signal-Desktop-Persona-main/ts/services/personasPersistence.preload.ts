// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — keeping a member's ZK state across restarts.
//
// The engine used to live only in memory, so every restart, crash or server reset left
// the member with a brand-new object and an empty replica. Its later posts then built on
// a history nobody else had, and every peer held them back forever: persona posts
// silently stopped working for that member. Two things are saved, PER PERSONAS GROUP (in a
// folder named by the group's phantom bundle, so a new bundle starts fresh):
//
//   state.bin    ENCRYPTED. The member's zk object (Engine.exportMemberState) — its
//                persona secret — plus the pseudonym and topic lists. AES-256-GCM under a
//                key derived in the main process from Signal's database key, which the OS
//                keychain protects (safeStorage). Without that key nothing is written and
//                the engine stays in memory only, as before: the secret is never stored
//                in the clear.
//   journal.bin  The records the replica has seen, written by the engine itself as it
//                accepts each one. Public data — every member holds the same records.
//
// THE ORDERING RULE. Every record reveals the nullifier of the object it spends. If a
// restart restored an object OLDER than one already spent by a record that went out,
// the member would spend it again, and two records with one nullifier are provably from
// the same member — an anonymous post linked to its author. So the state an emit
// produces is saved, synchronously and durably, BEFORE that record is handed to Signal to
// send (see personasEngine `persistAfterEmit`), and a failed save refuses the send and
// deletes the older file rather than leave it to be restored.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { join } from 'node:path';

import { ipcRenderer } from 'electron';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  getPersonasGroupIds,
  getPhantomBundleFingerprint,
} from './personasPhantom.preload.ts';

const log = createLogger('personasPersistence');

const MAGIC = Buffer.from('PZS1');
const IV_BYTES = 12;
const TAG_BYTES = 16;

type Storage = { key: Buffer<ArrayBuffer>; dir: string };

let storage: Storage | undefined;
let initialized: Promise<void> | undefined;

// One per personas group: the folder its state lives in (named by the group's bundle),
// and the member state most recently saved for it.
type GroupState = { folder: string; lastMemberState?: Buffer<ArrayBuffer> };
const groups = new Map<string, GroupState>();

// Small app-side lists that belong with a group's member (pseudonym nonces, topic
// contexts, ...). Their modules register here, so this module does not import them; each
// keeps its own per-group values.
type Extra = {
  snapshot: (groupId: string) => unknown;
  restore: (groupId: string, value: unknown) => void;
};
const extras = new Map<string, Extra>();

export function registerPersistedExtra(name: string, extra: Extra): void {
  extras.set(name, extra);
}

/** Fetch the state key from the main process. Call (and await) before building an engine. */
export function initPersonasPersistence(): Promise<void> {
  // One shared promise: each group warms its engine at startup, and a caller that returned
  // before the key arrived would build its engine with no storage. That member starts
  // new on every restart, and nothing it spends is saved.
  initialized ??= fetchStateStorage();
  return initialized;
}

async function fetchStateStorage(): Promise<void> {
  try {
    const result = (await ipcRenderer.invoke('personas:state-storage')) as
      | { key: string; dir: string }
      | undefined;
    if (result) {
      storage = { key: Buffer.from(result.key, 'hex'), dir: result.dir };
      log.info('state persistence enabled (encrypted)');
    } else {
      log.warn('no state key available: the ZK engines stay in memory only');
    }
  } catch (error) {
    log.error(`state persistence unavailable: ${toLogFormat(error)}`);
  }
}

function groupDir(groupId: string): string | undefined {
  const state = groups.get(groupId);
  if (!storage || !state) {
    return undefined;
  }
  return join(storage.dir, state.folder);
}

/**
 * Select a group's state folder (named by its phantom bundle and protocol version) and
 * return its journal path, creating the folder. Folders of bundles this member no longer
 * holds are deleted: those groups are gone (a server reset, a new bundle), and their
 * persona secrets should not linger on disk.
 */
export function openPersonasGroupState(
  groupId: string,
  folder: string
): { journalPath: string } | undefined {
  if (!storage) {
    return undefined;
  }
  groups.set(groupId, { folder });
  const dir = join(storage.dir, folder);
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const keep = new Set(
      getPersonasGroupIds()
        .map(id => getPhantomBundleFingerprint(id))
        .filter((fp): fp is string => fp != null)
        .map(fp => `${fp}-v3`)
    );
    keep.add(folder);
    for (const entry of readdirSync(storage.dir)) {
      if (!keep.has(entry)) {
        rmSync(join(storage.dir, entry), { recursive: true, force: true });
        log.info(`removed saved state of a group we no longer hold (${entry})`);
      }
    }
  } catch (error) {
    log.error(`could not prepare ${dir}: ${toLogFormat(error)}`);
    groups.delete(groupId);
    return undefined;
  }
  return { journalPath: join(dir, 'journal.bin') };
}

/**
 * The saved member state for a group, restoring the registered extras along the way.
 * undefined when there is none (a new member) or it cannot be read.
 */
export function loadPersonasState(groupId: string): Buffer<ArrayBuffer> | undefined {
  const dir = groupDir(groupId);
  const state = groups.get(groupId);
  if (!storage || !dir || !state) {
    return undefined;
  }
  const path = join(dir, 'state.bin');
  if (!existsSync(path)) {
    return undefined;
  }
  try {
    const raw = readFileSync(path);
    if (
      raw.length < MAGIC.length + IV_BYTES + TAG_BYTES ||
      !raw.subarray(0, 4).equals(MAGIC)
    ) {
      throw new Error('not a personas state file');
    }
    const iv = raw.subarray(4, 4 + IV_BYTES);
    const tag = raw.subarray(4 + IV_BYTES, 4 + IV_BYTES + TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', storage.key, iv);
    decipher.setAAD(Buffer.from(`personas-state|${state.folder}`));
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([
      decipher.update(raw.subarray(4 + IV_BYTES + TAG_BYTES)),
      decipher.final(),
    ]);
    const parsed = JSON.parse(plain.toString('utf8')) as {
      member?: string;
      extras?: Record<string, unknown>;
    };
    for (const [name, extra] of extras) {
      if (parsed.extras && name in parsed.extras) {
        extra.restore(groupId, parsed.extras[name]);
      }
    }
    state.lastMemberState = parsed.member
      ? Buffer.from(parsed.member, 'base64')
      : undefined;
    log.info('loaded saved member state');
    return state.lastMemberState;
  } catch (error) {
    // Unreadable (wrong key after a keychain reset, or damage). Move it aside rather than
    // overwrite it silently; the engine starts a new member, which is safe — a new object
    // shares no nullifier with the old one.
    log.error(
      `saved member state unreadable, starting a new member: ${toLogFormat(error)}`
    );
    try {
      renameSync(path, `${path}.unreadable-${Date.now()}`);
    } catch {
      // best effort
    }
    return undefined;
  }
}

/**
 * Save a group's member state (and the extras), durably, before the record it belongs to
 * is sent. Returns false if it could not be saved — the caller must then NOT send. With
 * no state key there is nothing on disk to go stale, so this succeeds trivially.
 */
export function savePersonasState(
  groupId: string,
  memberState: Buffer<ArrayBuffer> | undefined | null
): boolean {
  const state = groups.get(groupId);
  if (state && memberState) {
    state.lastMemberState = memberState;
  }
  const dir = groupDir(groupId);
  if (!storage || !dir || !state) {
    return true;
  }
  const path = join(dir, 'state.bin');
  const tmp = `${path}.tmp`;
  try {
    const payload = Buffer.from(
      JSON.stringify({
        member: state.lastMemberState?.toString('base64'),
        extras: Object.fromEntries(
          [...extras].map(([name, extra]) => [name, extra.snapshot(groupId)])
        ),
      }),
      'utf8'
    );
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', storage.key, iv);
    cipher.setAAD(Buffer.from(`personas-state|${state.folder}`));
    const body = Buffer.concat([cipher.update(payload), cipher.final()]);
    const fd = openSync(tmp, 'w', 0o600);
    try {
      writeSync(fd, Buffer.concat([MAGIC, iv, cipher.getAuthTag(), body]));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
    return true;
  } catch (error) {
    log.error(
      `could not save member state; refusing to send: ${toLogFormat(error)}`
    );
    // Never leave an OLDER state behind to be restored after this record goes out
    // some other way: delete it. A restart then starts a new member, which is safe.
    rmSync(path, { force: true });
    rmSync(tmp, { force: true });
    return false;
  }
}

/** Re-save a group after one of its extras (pseudonyms, topics, ...) changed. */
export function personasExtrasChanged(groupId: string | undefined): void {
  if (groupId && groups.get(groupId)?.lastMemberState) {
    savePersonasState(groupId, undefined);
  }
}
