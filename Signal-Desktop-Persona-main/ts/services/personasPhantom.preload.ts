// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo, Phase 5 — the shared phantom identity that gives recipient-
// anonymity. Every member sends group messages under ONE shared sender
// certificate + ONE shared group sender key, so a recipient (even an
// instrumented member) sees byte-identical Signal sender metadata for everyone;
// the only attribution is the persona carried in the ZK record. Proven at the
// libsignal level in scratchpad/phantom-gate.mjs.
//
// The three shared secrets (see the gate):
//   1. the phantom IDENTITY keypair (it IS the cert's senderKey; sealed-sender
//      auth binds the private key to the cert, so members must share it),
//   2. the phantom SenderCertificate (signed by a trust root we mint and add to
//      config.serverTrustRoots so Desktop's receive-side validateWithTrustRoots
//      admits it),
//   3. the advancing group sender key under a shared distributionId.
//
// This module owns the bundle and its distribution, with no shared folder or server:
//
//   MINT     the member who creates a group mints the bundle (mintPhantomBundle), or an
//            admin turns personas on in an existing group (turnOnPersonasInGroup);
//   SHARE    any member holding it sends it 1:1 to each fellow member OF THAT GROUP who
//            does not have it yet, over the pairwise Double Ratchet
//            (distributePhantomBundle);
//   ADOPT    a member adopts the FIRST bundle it gets for a group from a fellow member
//            of that group, and refuses any different one afterwards
//            (adoptPhantomBundle).
//
// The bundle lives in item storage (the encrypted DB). Delivery rides Desktop's real
// GroupV2 sender-key path — the phantom lives only INSIDE the sealed envelope; the real
// account still authorizes delivery as a group member.
//
// A BUNDLE BELONGS TO ONE GROUP (version 2). Each group has its own phantom identity,
// chain (its own distribution id) and barrier schedule, and so its own persona engine,
// state and personas: none of it is shared with another group. An account takes part in
// at most MAX_PERSONAS_GROUPS personas groups (each extra member is its own account). A
// version 1 bundle named no group and was shared across all of them; it is discarded.
//
// Gated on the same signals as the rest of the demo (isPersonasEngineEnabled's env).

import { createHash, randomUUID } from 'node:crypto';

import {
  IdentityKeyPair,
  PublicKey,
  PrivateKey,
  ProtocolAddress,
  ServerCertificate,
  SenderCertificate,
  SenderKeyRecord,
  SenderKeyDistributionMessage,
  SenderKeyStore,
  IdentityKeyStore,
  groupEncrypt,
} from '@signalapp/libsignal-client';
import type {
  CiphertextMessage,
  Direction,
  IdentityChange,
} from '@signalapp/libsignal-client';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import * as Bytes from '../Bytes.std.ts';
import type { ConversationModel } from '../models/conversations.preload.ts';
import { isGroupV2, isMe } from '../util/whatTypeOfConversation.dom.ts';
import {
  encodePhantomBundle,
  type PersonaPhantomBundleWire,
} from './personasCarriage.std.ts';
import {
  PHANTOM_SENDER_ACI,
  addExpectedPhantomCertificate,
} from './personasPhantomCert.std.ts';
import {
  signalProtocolStore,
  GLOBAL_ZONE,
} from '../SignalProtocolStore.preload.ts';
import { SenderKeys } from '../LibSignalStores.node.ts';
import { QualifiedAddress } from '../types/QualifiedAddress.std.ts';
import { Address } from '../types/Address.std.ts';
import type { ServiceIdString } from '../types/ServiceId.std.ts';
import { normalizeServiceId } from '../types/ServiceId.std.ts';
import { itemStorage } from '../textsecure/Storage.preload.ts';
import { drop } from '../util/drop.std.ts';

const log = createLogger('personasPhantom');

// Fixed demo identifiers. All instances must agree; these are constants (not
// secrets) so a late joiner that loads the bundle still uses the same address.
const PHANTOM_ACI: ServiceIdString = normalizeServiceId(
  PHANTOM_SENDER_ACI,
  'personasPhantom'
);
const PHANTOM_DEVICE_ID = 1;

// Cert lifetime: minted once, must outlive any demo message's serverTimestamp.
const TEN_YEARS_MS = 10 * 365 * 24 * 3600 * 1000;

// The barrier period a minted bundle carries (PERSONAS_BARRIER_PERIOD_MS overrides).
const DEFAULT_BARRIER_PERIOD_MS = 10_000;

// How often a bundle holder checks its groups for members who still need the bundle.
const DISTRIBUTION_INTERVAL_MS = 30_000;

// Recorded in item storage once this member's chain is installed, so a reboot keeps a
// chain that has walked forward instead of resetting it. Versioned: chains installed by
// the old receive-only (SKDM) path have no signing key and cannot send, so they must be
// replaced once.
const CHAIN_MARKER_VERSION = 'full-v1';

// Identifies a bundle. The trust root is minted fresh for each bundle and is public,
// so hashing it distinguishes bundles without writing key material to disk in a new
// place. Truncated: this only has to be distinct, not collision-resistant.
const bundleFingerprint = (mat: PhantomMaterial): string =>
  createHash('sha256')
    .update(mat.trustRootPublicBase64)
    .digest('hex')
    .slice(0, 16);

export const phantomAddress = (): ProtocolAddress =>
  ProtocolAddress.new(PHANTOM_ACI, PHANTOM_DEVICE_ID);

export const getPhantomAci = (): ServiceIdString => PHANTOM_ACI;

// The immutable, shared phantom bundle (all fields base64), as kept in item storage.
type SerializedBundle = {
  // The Signal group (GroupV2 id) this bundle is for.
  groupId: string;
  // Public key of the trust root we mint; goes into config.serverTrustRoots.
  trustRootPublic: string;
  // The shared phantom identity keypair (private state — the load-bearing secret).
  phantomIdentityKeyPair: string;
  // The shared sender certificate (binds phantom ACI/device/identity key).
  phantomCert: string;
  // Distribution id for the shared group sender key.
  distributionId: string;
  // SenderKeyDistributionMessage receivers process to install the receive chain.
  skdm: string;
  // Initial SenderKeyRecord senders load to seed the shared send chain.
  sendKeyRecord: string;
  // The shared barrier schedule; the creator picks it so every member agrees.
  schedule: { anchorMs: number; periodMs: number };
};

// A minimal in-memory SenderKeyStore (the phantom key is deliberately kept OUT
// of Desktop's DB store; the send chain is roster-dir-backed instead). Mirrors
// the store used in the bring-up gate.
class MemSenderKeyStore extends SenderKeyStore {
  #map = new Map<string, Uint8Array<ArrayBuffer>>();

  #key(sender: ProtocolAddress, distId: string): string {
    return `${sender.name()}::${sender.deviceId()}::${distId}`;
  }

  async saveSenderKey(
    sender: ProtocolAddress,
    distId: string,
    record: SenderKeyRecord
  ): Promise<void> {
    this.#map.set(this.#key(sender, distId), record.serialize());
  }

  async getSenderKey(
    sender: ProtocolAddress,
    distId: string
  ): Promise<SenderKeyRecord | null> {
    const bytes = this.#map.get(this.#key(sender, distId));
    return bytes ? SenderKeyRecord.deserialize(bytes) : null;
  }

  rawGet(
    sender: ProtocolAddress,
    distId: string
  ): Uint8Array<ArrayBuffer> | undefined {
    return this.#map.get(this.#key(sender, distId));
  }

  rawSet(
    sender: ProtocolAddress,
    distId: string,
    bytes: Uint8Array<ArrayBuffer>
  ): void {
    this.#map.set(this.#key(sender, distId), bytes);
  }
}

// An IdentityKeyStore that presents the PHANTOM identity as the LOCAL identity (so
// the sealed-sender authentication tag matches the phantom certificate for every
// member), while DELEGATING every recipient-facing lookup to Desktop's real identity
// store. `sealedSenderMultiRecipientEncrypt` requires each recipient's identity to be
// known (otherwise it reports "session not found"), and the real store already holds
// them — only the local *sending* identity is swapped. Proven at the libsignal level
// in scratchpad/phantom-gate-multi.mjs.
class PhantomIdentityStore extends IdentityKeyStore {
  #identity: IdentityKeyPair;
  #delegate: IdentityKeyStore;

  constructor(identity: IdentityKeyPair, delegate: IdentityKeyStore) {
    super();
    this.#identity = identity;
    this.#delegate = delegate;
  }

  async getIdentityKey(): Promise<PrivateKey> {
    // The load-bearing swap: the local identity is the phantom, so the outer
    // sealed-sender auth is byte-indistinguishable across all real senders.
    return this.#identity.privateKey;
  }

  async getLocalRegistrationId(): Promise<number> {
    return this.#delegate.getLocalRegistrationId();
  }

  async saveIdentity(
    name: ProtocolAddress,
    key: PublicKey
  ): Promise<IdentityChange> {
    return this.#delegate.saveIdentity(name, key);
  }

  async isTrustedIdentity(
    name: ProtocolAddress,
    key: PublicKey,
    direction: Direction
  ): Promise<boolean> {
    return this.#delegate.isTrustedIdentity(name, key, direction);
  }

  async getIdentity(name: ProtocolAddress): Promise<PublicKey | null> {
    return this.#delegate.getIdentity(name);
  }
}

// The loaded, live phantom material (deserialized once per process).
export type PhantomMaterial = {
  groupId: string;
  trustRootPublicBase64: string;
  phantomIdentity: IdentityKeyPair;
  phantomCert: SenderCertificate;
  distributionId: string;
  skdm: SenderKeyDistributionMessage;
  // The chain record this member's copy is installed from: the minter's fresh chain, or
  // the distributor's position at the time it sent the bundle.
  initialSendKeyRecord: Uint8Array<ArrayBuffer>;
  schedule: { anchorMs: number; periodMs: number };
};

// At most this many personas groups per account (each extra member is its own account).
export const MAX_PERSONAS_GROUPS = 3;

// The bundles this member holds, by Signal group id, with the JSON they were stored as.
const held = new Map<string, { mat: PhantomMaterial; json: string }>();

// The held groups that count toward MAX_PERSONAS_GROUPS: those this account is still in,
// and that an admin has not ended. A bundle is never released (being re-added to a group
// must find it again), so without this a group that was left, deleted or ended in Signal
// kept its place forever, and an account that had tried personas in three groups could
// never start a fourth. (An ended group keeps its members, hence the separate check.)
function liveGroupIds(): Array<string> {
  const ourAci = itemStorage.user.getAci();
  return [...held.keys()].filter(groupId => {
    const conversation = window.ConversationController.get(groupId);
    if (!conversation || conversation.get('left') || conversation.get('terminated')) {
      return false;
    }
    return ourAci == null || conversation.hasMember(ourAci);
  });
}

function atGroupLimit(): boolean {
  return liveGroupIds().length >= MAX_PERSONAS_GROUPS;
}
let loaded = false;
const readyListeners: Array<(mat: PhantomMaterial) => void> = [];

function isPersonasMode(): boolean {
  return Boolean(
    process.env.PERSONAS_AUTO_REGISTER || process.env.PERSONAS_KEYS_DIR
  );
}

function b64(bytes: Uint8Array<ArrayBuffer>): string {
  return Bytes.toBase64(bytes);
}
function unb64(s: string): Uint8Array<ArrayBuffer> {
  return Bytes.fromBase64(s);
}

// Mint a fresh bundle for `groupId`. Only the group's creator (or an admin turning
// personas on) does this; everyone else adopts. Each bundle has its own distribution id,
// so the groups' phantom chains never collide in the sender-key store.
async function generateBundle(groupId: string): Promise<SerializedBundle> {
  const trustRoot = IdentityKeyPair.generate();
  const serverKey = IdentityKeyPair.generate();
  const serverCert = ServerCertificate.new(1, serverKey.publicKey, trustRoot.privateKey);

  const phantomIdentity = IdentityKeyPair.generate();
  const expiration = Date.now() + TEN_YEARS_MS;
  const phantomCert = SenderCertificate.new(
    PHANTOM_ACI,
    null,
    PHANTOM_DEVICE_ID,
    phantomIdentity.publicKey,
    expiration,
    serverCert,
    serverKey.privateKey
  );

  const distributionId = randomUUID();
  const generatorStore = new MemSenderKeyStore();
  const skdm = await SenderKeyDistributionMessage.create(
    phantomAddress(),
    distributionId,
    generatorStore
  );
  const sendKeyRecord = generatorStore.rawGet(phantomAddress(), distributionId);
  if (!sendKeyRecord) {
    throw new Error('generateBundle: generator store missing sender key record');
  }

  const period = Number(process.env.PERSONAS_BARRIER_PERIOD_MS);
  return {
    groupId,
    trustRootPublic: b64(trustRoot.publicKey.serialize()),
    phantomIdentityKeyPair: b64(phantomIdentity.serialize()),
    phantomCert: b64(phantomCert.serialize()),
    distributionId,
    skdm: b64(skdm.serialize()),
    sendKeyRecord: b64(sendKeyRecord),
    schedule: {
      anchorMs: Date.now(),
      periodMs: period > 0 ? period : DEFAULT_BARRIER_PERIOD_MS,
    },
  };
}

function deserialize(bundle: SerializedBundle): PhantomMaterial {
  return {
    groupId: bundle.groupId,
    trustRootPublicBase64: bundle.trustRootPublic,
    phantomIdentity: IdentityKeyPair.deserialize(unb64(bundle.phantomIdentityKeyPair)),
    phantomCert: SenderCertificate.deserialize(unb64(bundle.phantomCert)),
    distributionId: bundle.distributionId,
    skdm: SenderKeyDistributionMessage.deserialize(unb64(bundle.skdm)),
    initialSendKeyRecord: unb64(bundle.sendKeyRecord),
    schedule: bundle.schedule,
  };
}

function activate(json: string, how: string): PhantomMaterial {
  const mat = deserialize(JSON.parse(json) as SerializedBundle);
  held.set(mat.groupId, { mat, json });
  addExpectedPhantomCertificate(mat.phantomCert.serialize());
  log.info(`phantom bundle ${bundleFingerprint(mat)} ${how}`);
  return mat;
}

async function saveHeld(): Promise<void> {
  const out: Record<string, string> = {};
  for (const [groupId, { json }] of held) {
    out[groupId] = json;
  }
  await itemStorage.put('personasPhantomBundles', JSON.stringify(out));
}

// Load every bundle this member holds from item storage, once. Migrates the single
// bundle earlier builds stored, and drops a version 1 bundle (it named no group).
async function loadHeld(): Promise<void> {
  if (loaded || !isPersonasMode()) {
    return;
  }
  loaded = true;
  loadPending();
  try {
    const all = itemStorage.get('personasPhantomBundles');
    if (all) {
      for (const json of Object.values(JSON.parse(all) as Record<string, string>)) {
        try {
          activate(json, 'loaded from storage');
        } catch (error) {
          log.error(`loadHeld: a stored bundle is unreadable: ${toLogFormat(error)}`);
        }
      }
    }
    const single = itemStorage.get('personasPhantomBundle');
    if (single) {
      if ((JSON.parse(single) as Partial<SerializedBundle>).groupId) {
        activate(single, 'migrated from the single-group store');
        await saveHeld();
      } else {
        log.warn('loadHeld: discarding a bundle that names no group (version 1)');
        await itemStorage.remove('personasPhantomSentTo');
      }
      await itemStorage.remove('personasPhantomBundle');
    }
  } catch (error) {
    log.error(`loadHeld: stored bundles unreadable: ${toLogFormat(error)}`);
  }
}

// The bundle this member holds for `groupId`, if any.
export async function ensurePhantomMaterial(
  groupId: string | undefined
): Promise<PhantomMaterial | undefined> {
  await loadHeld();
  return groupId ? held.get(groupId)?.mat : undefined;
}

// Every bundle this member holds.
export function allPhantomMaterial(): ReadonlyArray<PhantomMaterial> {
  return [...held.values()].map(({ mat }) => mat);
}

export function hasPhantomMaterial(groupId: string | undefined): boolean {
  return groupId != null && held.has(groupId);
}

// The Signal groups (GroupV2 ids) this install uses personas in.
export function getPersonasGroupIds(): ReadonlyArray<string> {
  return [...held.keys()];
}

// Whether `conversation` is one of this install's personas groups.
export function isPersonasGroup(conversation: ConversationModel | undefined): boolean {
  const groupId = conversation?.get('groupId');
  return groupId != null && held.has(groupId);
}

// How persona features stand in `conversation`, for the composer: personas are on here;
// they are not on here yet; or not on here and this account is already in its maximum
// number of personas groups (named, so the person knows which).
export type PersonasGroupStanding =
  | { kind: 'this' }
  | { kind: 'none' }
  | { kind: 'full'; names: ReadonlyArray<string> };

export function personasGroupStanding(
  conversation: ConversationModel | undefined
): PersonasGroupStanding {
  if (isPersonasGroup(conversation)) {
    return { kind: 'this' };
  }
  if (!atGroupLimit()) {
    return { kind: 'none' };
  }
  return {
    kind: 'full',
    names: liveGroupIds().map(
      groupId => window.ConversationController.get(groupId)?.getTitle() ?? 'a group'
    ),
  };
}

// Which bundle a group's saved engine state is keyed by, so a new bundle for the group
// (after a server reset, say) starts from a fresh member and replica.
export function getPhantomBundleFingerprint(groupId: string | undefined): string | undefined {
  const mat = groupId ? held.get(groupId)?.mat : undefined;
  return mat ? bundleFingerprint(mat) : undefined;
}

export function getPhantomSchedule(
  groupId: string | undefined
): PhantomMaterial['schedule'] | undefined {
  return groupId ? held.get(groupId)?.mat.schedule : undefined;
}

// Called with each bundle once it is available: right away for those already held, and
// as more are minted or adopted. Background uses this to admit each trust root and
// build each group's engine on its bundle's schedule.
export function onPhantomMaterialReady(listener: (mat: PhantomMaterial) => void): void {
  readyListeners.push(listener);
  for (const { mat } of held.values()) {
    listener(mat);
  }
}

async function commitBundle(json: string, how: string): Promise<PhantomMaterial> {
  const mat = activate(json, how);
  await saveHeld();
  await installPhantomChain(mat.groupId);
  for (const listener of readyListeners) {
    try {
      listener(mat);
    } catch (error) {
      log.error(`phantom ready listener failed: ${toLogFormat(error)}`);
    }
  }
  return mat;
}

// The group creator mints the group's bundle — unless this account is already in its
// maximum number of personas groups.
export async function mintPhantomBundle(
  groupId: string | undefined
): Promise<PhantomMaterial | undefined> {
  if (!isPersonasMode() || !groupId) {
    return undefined;
  }
  const existing = await ensurePhantomMaterial(groupId);
  if (existing) {
    return existing;
  }
  if (atGroupLimit()) {
    log.info(
      `mintPhantomBundle: already in ${MAX_PERSONAS_GROUPS} personas groups; not minting`
    );
    return undefined;
  }
  return commitBundle(JSON.stringify(await generateBundle(groupId)), 'minted');
}

export type TurnOnResult =
  | { ok: true }
  | { ok: false; reason: string };

// An ADMIN turns personas on in an existing group that has none: mints the group's
// bundle and shares it with the members. Only ONE admin should do this per group — two
// bundles minted at once for one group would split it, and each member keeps the first
// it receives.
export async function turnOnPersonasInGroup(
  conversation: ConversationModel
): Promise<TurnOnResult> {
  if (!isPersonasMode()) {
    return { ok: false, reason: 'personas are not enabled in this app' };
  }
  const groupId = conversation.get('groupId');
  if (!isGroupV2(conversation.attributes) || !groupId) {
    return { ok: false, reason: 'personas work in groups only' };
  }
  if (!conversation.areWeAdmin()) {
    return { ok: false, reason: 'only a group admin can turn personas on' };
  }
  if (await ensurePhantomMaterial(groupId)) {
    return { ok: true };
  }
  if (atGroupLimit()) {
    return {
      ok: false,
      reason: `this account already uses personas in ${MAX_PERSONAS_GROUPS} groups`,
    };
  }
  await mintPhantomBundle(groupId);
  await distributePhantomBundle();
  return { ok: true };
}

export type AdoptResult = 'adopted' | 'duplicate' | 'conflict' | 'full' | 'disabled';

// Adopt a bundle received from a fellow member of the group it names. The caller must
// already have checked that it is an admin of the group (isFellowGroupMember).
//
// FIRST ONE WINS, AND IT IS FINAL, per group. A second, different bundle for a group is
// refused: switching would silently strand our chain, and a member being fed a different
// certificate is exactly what tagging would look like. Logged loudly instead.
export async function adoptPhantomBundle(
  wire: PersonaPhantomBundleWire,
  from: string
): Promise<AdoptResult> {
  if (!isPersonasMode()) {
    return 'disabled';
  }
  const existing = await ensurePhantomMaterial(wire.groupId);
  if (existing) {
    const same =
      existing.trustRootPublicBase64 === wire.trustRootPublic &&
      b64(existing.phantomCert.serialize()) === wire.phantomCert;
    if (same) {
      log.info(`adoptPhantomBundle: already hold this bundle; ignoring copy from ${from}`);
      return 'duplicate';
    }
    log.error(
      `adoptPhantomBundle: REFUSED a different phantom bundle for this group from ${from}. ` +
        `We hold ${bundleFingerprint(existing)}. Either two admins turned personas on at ` +
        'once or someone is handing members different certificates; either way, ' +
        'switching would strand this member.'
    );
    return 'conflict';
  }
  if (atGroupLimit()) {
    log.warn(
      `adoptPhantomBundle: not adopting a bundle from ${from} yet: this account already ` +
        `uses personas in ${MAX_PERSONAS_GROUPS} groups (kept; adopted once it leaves one)`
    );
    return 'full';
  }
  const bundle: SerializedBundle = {
    groupId: wire.groupId,
    trustRootPublic: wire.trustRootPublic,
    phantomIdentityKeyPair: wire.phantomIdentityKeyPair,
    phantomCert: wire.phantomCert,
    distributionId: wire.distributionId,
    skdm: wire.skdm,
    sendKeyRecord: wire.chainRecord,
    schedule: wire.schedule,
  };
  await commitBundle(JSON.stringify(bundle), `adopted from ${from}`);
  return 'adopted';
}

// Whether a conversation (the 1:1 chat a bundle arrived in) belongs to someone who is a
// full member of `groupId`, a group we are in. Bundles from anyone else are ignored.
//
// An admin, not just any member: the first bundle is final, so one from an ordinary member
// who got there first could cut a newcomer off from the group and read all they send.
export function isFellowGroupMember(conversationId: string, groupId: string): boolean {
  const group = window.ConversationController.get(groupId);
  const serviceId = window.ConversationController.get(conversationId)?.getServiceId();
  return (
    group != null &&
    isGroupV2(group.attributes) &&
    !group.get('left') &&
    group.getMemberConversationIds().has(conversationId) &&
    serviceId != null &&
    group.isAdmin(serviceId)
  );
}

// Bundles not adopted yet: from someone who was not (yet) a fellow group member, or
// refused because this account was at its group limit.
//
// The creator sends the bundle the moment it adds a member, so the 1:1 bundle can beat
// the group update that tells this member it was added. Dropping it then would be
// permanent: the sender has already marked us as sent. Likewise a bundle refused at the
// limit: leaving a group later must not leave this one without personas for good. So it
// is held and re-checked on every sweep, adopted once the sender is a fellow member and
// there is room. Persisted (a restart must not lose it), bounded, and never adopted
// without the membership check.
const MAX_PENDING_BUNDLES = 8;
const pendingBundles = new Map<
  string,
  { wire: PersonaPhantomBundleWire; from: string; conversationId: string }
>();

export function holdPendingBundle(
  conversationId: string,
  wire: PersonaPhantomBundleWire,
  from: string
): void {
  const key = `${conversationId}:${wire.groupId}`;
  if (!pendingBundles.has(key) && pendingBundles.size >= MAX_PENDING_BUNDLES) {
    log.warn(`holdPendingBundle: too many pending bundles; dropping the one from ${from}`);
    return;
  }
  pendingBundles.set(key, { wire, from, conversationId });
  log.info(`holdPendingBundle: holding a bundle from ${from} until it can be adopted`);
  drop(savePending());
}

async function savePending(): Promise<void> {
  await itemStorage.put(
    'personasPhantomPending',
    JSON.stringify(Object.fromEntries(pendingBundles))
  );
}

function loadPending(): void {
  const stored = itemStorage.get('personasPhantomPending');
  if (!stored) {
    return;
  }
  try {
    for (const [key, value] of Object.entries(
      JSON.parse(stored) as Record<
        string,
        { wire: PersonaPhantomBundleWire; from: string; conversationId: string }
      >
    )) {
      pendingBundles.set(key, value);
    }
  } catch (error) {
    log.error(`loadPending: stored pending bundles unreadable: ${toLogFormat(error)}`);
  }
}

async function retryPendingBundles(): Promise<void> {
  let changed = false;
  for (const [key, { wire, from, conversationId }] of [...pendingBundles]) {
    if (held.has(wire.groupId)) {
      pendingBundles.delete(key);
      changed = true;
      continue;
    }
    if (isFellowGroupMember(conversationId, wire.groupId)) {
      // oxlint-disable-next-line no-await-in-loop
      const result = await adoptPhantomBundle(wire, from);
      if (result === 'full') {
        // Still no room: kept, and tried again next sweep.
        continue;
      }
      log.info(`retryPendingBundles: bundle from ${from}: ${result}`);
      pendingBundles.delete(key);
      changed = true;
    }
  }
  if (changed) {
    await savePending();
  }
}

// This member's current position on a group's shared chain, for handing to a new member.
async function readCurrentChainRecord(
  mat: PhantomMaterial
): Promise<Uint8Array<ArrayBuffer> | undefined> {
  const ourAci = itemStorage.user.getAci();
  if (!ourAci) {
    return undefined;
  }
  const store = new SenderKeys({
    signalProtocolStore,
    ourServiceId: ourAci,
    zone: GLOBAL_ZONE,
  });
  return signalProtocolStore.enqueueSenderKeyJob(
    phantomQualifiedAddress(ourAci),
    async () =>
      (await store.getSenderKey(phantomAddress(), mat.distributionId))?.serialize(),
    GLOBAL_ZONE
  );
}

let distributing = false;

// Send each bundle 1:1 to every full member of ITS group who has not been sent it yet.
// Any holder distributes, not only the creator, so a group does not depend on its
// creator staying online. Recipients ignore copies of a bundle they already hold.
export async function distributePhantomBundle(): Promise<void> {
  await loadHeld();
  if (distributing || held.size === 0) {
    return;
  }
  distributing = true;
  try {
    for (const { mat, json } of [...held.values()]) {
      // oxlint-disable-next-line no-await-in-loop
      await distributeOne(mat, json);
    }
  } finally {
    distributing = false;
  }
}

// Whether a member's join has reached this group's engine; undefined while unknown (no
// engine yet). Registered by personasEngine, which this module cannot import.
let memberHasJoined: (groupId: string, serviceId: string) => boolean | undefined = () =>
  undefined;
export function setPhantomJoinCheck(check: typeof memberHasJoined): void {
  memberHasJoined = check;
}

// A member we sent the bundle to whose join never arrived (it refused or lost the
// bundle) is sent it again, at most this often. In memory, so also once per restart.
const RESEND_EVERY_MS = 10 * 60_000;
const lastSentAt = new Map<string, number>();

async function distributeOne(mat: PhantomMaterial, json: string): Promise<void> {
  const fingerprint = bundleFingerprint(mat);
  const sent = new Set(itemStorage.get('personasPhantomSentTo') ?? []);
  const pending = new Map<string, ConversationModel>();
  const group = window.ConversationController.get(mat.groupId);
  // Members adopt a bundle only from an admin, so only an admin hands it out.
  if (group && isGroupV2(group.attributes) && !group.get('left') && group.areWeAdmin()) {
    for (const member of group.getMembers()) {
      const serviceId = member.getServiceId();
      if (!serviceId || isMe(member.attributes)) {
        continue;
      }
      const key = `${fingerprint}:${serviceId}`;
      if (!sent.has(key)) {
        pending.set(serviceId, member);
      } else if (
        memberHasJoined(mat.groupId, serviceId) === false &&
        Date.now() - (lastSentAt.get(key) ?? 0) >= RESEND_EVERY_MS
      ) {
        log.info(`distributePhantomBundle: ${serviceId} has not joined; sending it again`);
        pending.set(serviceId, member);
      }
    }
  }
  if (pending.size === 0) {
    return;
  }

  const chainRecord = await readCurrentChainRecord(mat);
  if (!chainRecord) {
    log.warn('distributePhantomBundle: no installed chain to share yet');
    return;
  }
  const stored = JSON.parse(json) as SerializedBundle;
  const body = encodePhantomBundle({
    v: 2,
    groupId: mat.groupId,
    trustRootPublic: stored.trustRootPublic,
    phantomIdentityKeyPair: stored.phantomIdentityKeyPair,
    phantomCert: stored.phantomCert,
    distributionId: stored.distributionId,
    skdm: stored.skdm,
    chainRecord: b64(chainRecord),
    schedule: stored.schedule,
  });

  // Sequential on purpose: each recipient is marked sent (and persisted) only after
  // its own send succeeded, so a failure retries just that member next sweep.
  for (const [serviceId, member] of pending) {
    try {
      // oxlint-disable-next-line no-await-in-loop
      await member.enqueueMessageForSend(
        { body, attachments: [] },
        // Key material: never shown, and only ever sent 1:1.
        { hideFromTimeline: true }
      );
      sent.add(`${fingerprint}:${serviceId}`);
      lastSentAt.set(`${fingerprint}:${serviceId}`, Date.now());
      // oxlint-disable-next-line no-await-in-loop
      await itemStorage.put('personasPhantomSentTo', [...sent]);
      log.info(`distributePhantomBundle: sent bundle ${fingerprint} to ${serviceId}`);
    } catch (error) {
      log.warn(
        `distributePhantomBundle: send to ${serviceId} failed (retrying next sweep): ` +
          toLogFormat(error)
      );
    }
  }
}

let distributionTimer: NodeJS.Timeout | undefined;

// Start the periodic sweep (boot, after registration): adopt held bundles whose sender
// has since become a fellow member, then distribute ours. Cheap when there is nothing
// to do.
export function startPhantomDistribution(): void {
  if (!isPersonasMode() || distributionTimer) {
    return;
  }
  const sweep = async () => {
    await retryPendingBundles();
    await distributePhantomBundle();
  };
  void sweep();
  distributionTimer = setInterval(() => {
    void sweep();
  }, DISTRIBUTION_INTERVAL_MS);
}

// Every held bundle's trust root (base64), for the receiver's trust-root set.
export function getPhantomTrustRootsBase64(): ReadonlyArray<string> {
  return [...held.values()].map(({ mat }) => mat.trustRootPublicBase64);
}

// Load stored bundles at boot, before MessageReceiver construction reads trust roots.
export async function warmPhantomMaterial(): Promise<void> {
  await loadHeld();
}

// Build the phantom identity store for a group's sealed-sender local identity,
// delegating recipient identity lookups to Desktop's real identity store (which already
// holds the group members' identities).
export function buildPhantomIdentityStore(
  groupId: string | undefined,
  delegate: IdentityKeyStore
): PhantomIdentityStore | undefined {
  const mat = groupId ? held.get(groupId)?.mat : undefined;
  if (!mat) {
    return undefined;
  }
  return new PhantomIdentityStore(mat.phantomIdentity, delegate);
}

const phantomQualifiedAddress = (ourAci: ServiceIdString): QualifiedAddress =>
  new QualifiedAddress(ourAci, Address.create(PHANTOM_ACI, PHANTOM_DEVICE_ID));

// THE SHARED PHANTOM CHAIN, ONE COPY PER MEMBER (per group).
//
// Every member holds its own copy of each group's shared sender-key chain: the FULL
// private SenderKeyRecord, signing key included, in Desktop's sender-key store under the
// phantom address and that group's distribution id. The same record serves both
// directions:
//
//   receive  groupDecrypt walks the copy forward past every post it sees
//            (MessageReceiver's sealed-sender path, keyed by the phantom address);
//   send     groupEncrypt continues from the step after the newest post seen
//            (phantomGroupEncrypt below, queued on the same address).
//
// THE ACCEPTED LIMITATION (design doc §4, Phase A1): two members posting at the same
// step, before either has seen the other's post, encrypt under the same message key.
// Recipients keep the first and drop the second as `DuplicatedMessage: old counter`.
export async function installPhantomChain(groupId?: string): Promise<void> {
  await loadHeld();
  const targets = groupId
    ? [held.get(groupId)?.mat].filter((m): m is PhantomMaterial => m != null)
    : allPhantomMaterial();
  for (const mat of targets) {
    // oxlint-disable-next-line no-await-in-loop
    await installOneChain(mat);
  }
}

async function installOneChain(mat: PhantomMaterial): Promise<void> {
  const ourAci = itemStorage.user.getAci();
  if (!ourAci) {
    log.warn('installPhantomChain: no ACI yet; skipping');
    return;
  }
  const address = phantomQualifiedAddress(ourAci);
  const store = new SenderKeys({
    signalProtocolStore,
    ourServiceId: ourAci,
    zone: GLOBAL_ZONE,
  });
  const marker = `${bundleFingerprint(mat)}:${CHAIN_MARKER_VERSION}`;
  // Markers of chains installed so far; the old single-chain marker counts too.
  const installed = new Set(itemStorage.get('personasPhantomChains') ?? []);
  const legacy = itemStorage.get('personasPhantomChain');
  if (legacy) {
    installed.add(legacy);
  }

  try {
    await signalProtocolStore.enqueueSenderKeyJob(
      address,
      async () => {
        const existing = await store.getSenderKey(
          phantomAddress(),
          mat.distributionId
        );
        // Keep a chain that has walked forward, but only when it provably came from
        // this bundle in the current format: a record under the same distribution id
        // from another bundle LOOKS valid while holding the wrong chain key, and every
        // phantom post would be dropped at this receiver.
        if (existing && installed.has(marker)) {
          log.info(`installPhantomChain: keeping chain ${marker}`);
          return;
        }
        if (existing) {
          log.warn(`installPhantomChain: replacing a stale chain with ${marker}`);
          // Delete first: saving over an existing record can leave a stale state
          // behind under the same chain id, and decryption keeps resolving to it.
          await signalProtocolStore.removeSenderKey(address, mat.distributionId);
        }
        await store.saveSenderKey(
          phantomAddress(),
          mat.distributionId,
          SenderKeyRecord.deserialize(mat.initialSendKeyRecord)
        );
        // Only after a successful install: a crash leaves no marker, read as stale.
        installed.add(marker);
        await itemStorage.put('personasPhantomChains', [...installed]);
        log.info(`installPhantomChain: installed chain ${marker}`);
      },
      GLOBAL_ZONE
    );
  } catch (error) {
    log.error(`installPhantomChain: failed: ${toLogFormat(error)}`);
  }
}

// Encrypt a persona post under this member's copy of a group's shared phantom chain.
// Queued on the phantom address, the same key MessageReceiver decrypts phantom posts
// under, so a send and a receive in this process never interleave on the record.
export async function phantomGroupEncrypt(
  groupId: string | undefined,
  message: Uint8Array<ArrayBuffer>
): Promise<CiphertextMessage> {
  const mat = groupId ? held.get(groupId)?.mat : undefined;
  if (!mat) {
    throw new Error('phantomGroupEncrypt: no phantom bundle for this group');
  }
  const { distributionId } = mat;
  const ourAci = itemStorage.user.getCheckedAci();
  const store = new SenderKeys({
    signalProtocolStore,
    ourServiceId: ourAci,
    zone: GLOBAL_ZONE,
  });
  return signalProtocolStore.enqueueSenderKeyJob(
    phantomQualifiedAddress(ourAci),
    () => groupEncrypt(phantomAddress(), distributionId, store, message),
    GLOBAL_ZONE
  );
}

export { MemSenderKeyStore, PhantomIdentityStore };
