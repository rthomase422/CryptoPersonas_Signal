// Copyright 2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import path from 'node:path';
import lodash from 'lodash';
import type { ThunkAction, ThunkDispatch } from 'redux-thunk';
import { v4 as generateUuid } from 'uuid';

import type { ReadonlyDeep } from 'type-fest';
import type {
  AddLinkPreviewActionType,
  RemoveLinkPreviewActionType,
} from './linkPreviews.preload.ts';
import type {
  AttachmentType,
  AttachmentDraftType,
  InMemoryAttachmentDraftType,
} from '../../types/Attachment.std.ts';
import {
  isImageAttachment,
  isVideoAttachment,
} from '../../util/Attachment.std.ts';
import { isViewOnceEligible } from '../../util/viewOnceEligibility.std.ts';
import { DataReader, DataWriter } from '../../sql/Client.preload.ts';
import type { BoundActionCreatorsMapObject } from '../../hooks/useBoundActions.std.ts';
import type { DraftBodyRanges } from '../../types/BodyRange.std.ts';
import type { LinkPreviewForUIType } from '../../types/message/LinkPreviews.std.ts';
import type {
  PinMessageData,
  ReadonlyMessageAttributesType,
} from '../../model-types.d.ts';
import { noopAction, type NoopActionType } from './noop.std.ts';
import type { ShowToastActionType } from './toast.preload.ts';
import type { StateType as RootStateType } from '../reducer.preload.ts';
import { createLogger } from '../../logging/log.std.ts';
import * as Errors from '../../types/errors.std.ts';
import type { PollCreateType } from '../../types/Polls.dom.ts';
import type { PreparedPersonaPost } from '../../services/personasRegistry.std.ts';
import { enqueuePollCreateForSend } from '../../util/enqueuePollCreateForSend.dom.ts';
import {
  ADD_PREVIEW as ADD_LINK_PREVIEW,
  REMOVE_PREVIEW as REMOVE_LINK_PREVIEW,
} from './linkPreviews.preload.ts';
import { LinkPreviewSourceType } from '../../types/LinkPreview.std.ts';
import type { AciString } from '../../types/ServiceId.std.ts';
import { completeRecording, getIsRecording } from './audioRecorder.preload.ts';
import { SHOW_TOAST, showToast } from './toast.preload.ts';
import type { AnyToast } from '../../types/Toast.dom.tsx';
import { ToastType } from '../../types/Toast.dom.tsx';
import { SafetyNumberChangeSource } from '../../types/SafetyNumberChangeSource.std.ts';
import { assignWithNoUnnecessaryAllocation } from '../../util/assignWithNoUnnecessaryAllocation.std.ts';
import {
  composePersonaPost,
  personaScanRequired,
  heldBadges,
  isPersonasEngineEnabled,
  type PersonaChoice,
} from '../../services/personasEngine.preload.ts';
import { turnOnPersonasInGroup } from '../../services/personasPhantom.preload.ts';
import { catchUpBlockReason } from '../../services/personasCatchUp.preload.ts';
import { ensurePersonaJoined } from '../../services/personasMembership.preload.ts';
import {
  createTopic,
  nameForContext,
} from '../../services/personasTopics.preload.ts';
import { getSelectedBadgeIfHeld } from '../../services/personasBadgeState.preload.ts';
import { sendAuthorshipClaim as doSendAuthorshipClaim } from '../../services/personasAuthorship.preload.ts';
import {
  createPseudonym,
  recordPetname,
  type PersonaPseudonym,
} from '../../services/personasPseudonyms.preload.ts';
import {
  getPersonaStatus,
  type PersonaStatus,
} from '../../services/personasStatus.preload.ts';
import {
  maybeSendPersonaRateForReaction,
  sendPersonaPoll,
  drainPersonaScans,
  ensureReadyForPersonaAction,
  runFullPersonaSweep,
  isPersonaBanned,
} from '../../services/personasActions.preload.ts';
import { blockSendUntilConversationsAreVerified } from '../../util/blockSendUntilConversationsAreVerified.dom.ts';
import { clearConversationDraftAttachments } from '../../util/clearConversationDraftAttachments.preload.ts';
import { deleteDraftAttachment } from '../../util/deleteDraftAttachment.preload.ts';
import {
  getLinkPreviewForSend,
  hasLinkPreviewLoaded,
  maybeGrabLinkPreview,
  removeLinkPreview,
  resetLinkPreview,
  suspendLinkPreviews,
} from '../../services/LinkPreview.preload.ts';
import {
  getAttachmentSizeLimit,
  getRenderDetailsForLimit,
  isAttachmentTooLargeToSend,
} from '../../types/AttachmentSize.std.ts';
import { getValue as getRemoteConfigValue } from '../../RemoteConfig.dom.ts';
import { getRecipientsByConversation } from '../../util/getRecipientsByConversation.dom.ts';
import { processAttachment } from '../../util/processAttachment.preload.ts';
import { hasDraftAttachments } from '../../util/hasDraftAttachments.std.ts';
import { isFileDangerous } from '../../util/isFileDangerous.std.ts';
import { stringToMIMEType } from '../../types/MIME.std.ts';
import { isNotNil } from '../../util/isNotNil.std.ts';
import { replaceIndex } from '../../util/replaceIndex.std.ts';
import { resolveAttachmentDraftData } from '../../util/resolveAttachmentDraftData.preload.ts';
import { resolveDraftAttachmentOnDisk } from '../../util/resolveDraftAttachmentOnDisk.preload.ts';
import { shouldShowInvalidMessageToast } from '../../util/shouldShowInvalidMessageToast.preload.ts';
import { writeDraftAttachment } from '../../util/writeDraftAttachment.preload.ts';
import { getMessageById } from '../../messages/getMessageById.preload.ts';
import { canReply, isNormalBubble } from '../selectors/message.preload.ts';
import { getAuthorId } from '../../messages/sources.preload.ts';
import { getConversationSelector } from '../selectors/conversations.dom.ts';
import { enqueueReactionForSend } from '../../reactions/enqueueReactionForSend.preload.ts';
import { enqueuePollTerminateForSend } from '../../polls/enqueuePollTerminateForSend.preload.ts';
import { useBoundActions } from '../../hooks/useBoundActions.std.ts';
import {
  CONVERSATION_UNLOADED,
  scrollToMessage,
} from './conversations.preload.ts';
import type {
  ConversationUnloadedActionType,
  TargetedConversationChangedActionType,
  ScrollToMessageActionType,
} from './conversations.preload.ts';
import { longRunningTaskWrapper } from '../../util/longRunningTaskWrapper.dom.tsx';
import { drop } from '../../util/drop.std.ts';
import { strictAssert } from '../../util/assert.std.ts';
import { makeQuote } from '../../util/makeQuote.preload.ts';
import { sendEditedMessage as doSendEditedMessage } from '../../util/sendEditedMessage.preload.ts';
import { Sound, SoundType } from '../../util/Sound.std.ts';
import {
  isImageTypeSupported,
  isVideoTypeSupported,
} from '../../util/GoogleChrome.std.ts';
import type { StateThunk } from '../types.std.ts';
import { itemStorage } from '../../textsecure/Storage.preload.ts';
import {
  getActivePanel,
  getSelectedConversationId,
} from '../selectors/nav.std.ts';
import { isPoll } from '../../messages/helpers.std.ts';
import type { Emoji } from '../../axo/emoji.std.ts';
import { isFeaturedEnabledNoRedux } from '../../util/isFeatureEnabled.dom.ts';
import {
  requestBadge as doRequestBadge,
  approveBadge as doApproveBadge,
  dismissBadgeRequest as doDismissBadgeRequest,
} from '../../services/personasBadgeFlow.preload.ts';
import { sendBadgeProof as doSendBadgeProof } from '../../services/personasBadgeProof.preload.ts';
import {
  approvePersonasReset as doApprovePersonaReset,
  dismissResetRequest as doDismissResetRequest,
  requestPersonasReset as doRequestPersonaReset,
} from '../../services/personasReset.preload.ts';
import { encodePostText } from '../../services/personasCarriage.std.ts';

const { debounce, isEqual } = lodash;

const log = createLogger('composer');

// State
// oxlint-disable-next-line signal-desktop/enforce-type-alias-readonlydeep
type ComposerStateByConversationType = {
  attachments: ReadonlyArray<AttachmentDraftType>;
  focusCounter: number;
  disabledCounter: number;
  isViewOnce: boolean;
  linkPreviewLoading: boolean;
  linkPreviewResult?: LinkPreviewForUIType;
  quotedMessage?: QuotedMessageForComposerType;
  sendCounter: number;
  shouldSendHighQualityAttachments?: boolean;
};

export type QuotedMessageForComposerType = ReadonlyDeep<{
  conversationId: ReadonlyMessageAttributesType['conversationId'];
  quote: ReadonlyMessageAttributesType['quote'] & {
    messageId?: string;
  };
}>;

// oxlint-disable-next-line signal-desktop/enforce-type-alias-readonlydeep
export type ComposerStateType = {
  conversations: Record<string, ComposerStateByConversationType>;
  // Personas demo: topics this instance knows about, each with the random `context`
  // that binds a rate-limited persona (persona = H(sk || context || i)). Learned from
  // announcements broadcast over the group, so all members converge on one context
  // per topic. Kept in redux purely so the composer (a renderer component that cannot
  // import preload modules) can render the picker.
  // Per personas group (GroupV2 id): each group has its own topics.
  personaTopics: Readonly<
    Record<string, ReadonlyArray<{ name: string; context: number }>>
  >;
  // Personas demo: the latest status snapshot, refreshed when the panel is opened.
  // Undefined until first read.
  personaStatus?: PersonaStatus;
  // Personas demo: unlimited pseudonyms this member has minted. Each is a nonce the
  // user can re-select, so a persona can post more than once instead of being a fresh
  // stranger every time.
  // Per personas group (GroupV2 id), like the topics.
  personaPseudonyms: Readonly<Record<string, ReadonlyArray<PersonaPseudonym>>>;
};

function getEmptyComposerState(): ComposerStateByConversationType {
  return {
    attachments: [],
    focusCounter: 0,
    disabledCounter: 0,
    isViewOnce: false,
    linkPreviewLoading: false,
    sendCounter: 0,
  };
}

export function getComposerStateForConversation(
  composer: ComposerStateType,
  conversationId: string
): ComposerStateByConversationType {
  return composer.conversations[conversationId] ?? getEmptyComposerState();
}

// Actions

const PERSONA_TOPIC_LEARNED = 'composer/PERSONA_TOPIC_LEARNED';
const PERSONA_STATUS_UPDATED = 'composer/PERSONA_STATUS_UPDATED';
const PERSONA_PSEUDONYMS_CHANGED = 'composer/PERSONA_PSEUDONYMS_CHANGED';
const ADD_PENDING_ATTACHMENT = 'composer/ADD_PENDING_ATTACHMENT';
const INCREMENT_SEND_COUNTER = 'composer/INCREMENT_SEND_COUNTER';
const REPLACE_ATTACHMENTS = 'composer/REPLACE_ATTACHMENTS';
const RESET_COMPOSER = 'composer/RESET_COMPOSER';
export const SET_FOCUS = 'composer/SET_FOCUS';
const SET_HIGH_QUALITY_SETTING = 'composer/SET_HIGH_QUALITY_SETTING';
const SET_QUOTED_MESSAGE = 'composer/SET_QUOTED_MESSAGE';
const SET_VIEW_ONCE = 'composer/SET_VIEW_ONCE';
const UPDATE_COMPOSER_DISABLED = 'composer/UPDATE_COMPOSER_DISABLED';

type AddPendingAttachmentActionType = ReadonlyDeep<{
  type: typeof ADD_PENDING_ATTACHMENT;
  payload: {
    conversationId: string;
    attachment: AttachmentDraftType;
  };
}>;

export type IncrementSendActionType = ReadonlyDeep<{
  type: typeof INCREMENT_SEND_COUNTER;
  payload: {
    conversationId: string;
  };
}>;

// oxlint-disable-next-line signal-desktop/enforce-type-alias-readonlydeep
export type ReplaceAttachmentsActionType = {
  type: typeof REPLACE_ATTACHMENTS;
  payload: {
    conversationId: string;
    attachments: ReadonlyArray<AttachmentDraftType>;
  };
};

export type ResetComposerActionType = ReadonlyDeep<{
  type: typeof RESET_COMPOSER;
  payload: {
    conversationId: string;
  };
}>;

type UpdateComposerDisabledActionType = ReadonlyDeep<{
  type: typeof UPDATE_COMPOSER_DISABLED;
  payload: {
    conversationId: string;
    value: boolean;
  };
}>;

export type SetFocusActionType = ReadonlyDeep<{
  type: typeof SET_FOCUS;
  payload: {
    conversationId: string;
  };
}>;

type SetHighQualitySettingActionType = ReadonlyDeep<{
  type: typeof SET_HIGH_QUALITY_SETTING;
  payload: {
    conversationId: string;
    value: boolean;
  };
}>;

// oxlint-disable-next-line signal-desktop/enforce-type-alias-readonlydeep
export type SetQuotedMessageActionType = {
  type: typeof SET_QUOTED_MESSAGE;
  payload: {
    conversationId: string;
    quotedMessage?: QuotedMessageForComposerType;
  };
};

export type SetViewOnceActionType = ReadonlyDeep<{
  type: typeof SET_VIEW_ONCE;
  payload: {
    conversationId: string;
    value: boolean;
  };
}>;

// oxlint-disable-next-line signal-desktop/enforce-type-alias-readonlydeep
type ComposerActionType =
  | PersonaTopicLearnedActionType
  | PersonaStatusUpdatedActionType
  | PersonaPseudonymsChangedActionType
  | AddLinkPreviewActionType
  | AddPendingAttachmentActionType
  | ConversationUnloadedActionType
  | IncrementSendActionType
  | RemoveLinkPreviewActionType
  | ReplaceAttachmentsActionType
  | ResetComposerActionType
  | TargetedConversationChangedActionType
  | UpdateComposerDisabledActionType
  | SetFocusActionType
  | SetHighQualitySettingActionType
  | SetQuotedMessageActionType
  | SetViewOnceActionType;

// Action Creators

// Personas demo: note a topic (created here or announced by a peer).
export type PersonaTopicLearnedActionType = ReadonlyDeep<{
  type: typeof PERSONA_TOPIC_LEARNED;
  payload: { groupId: string; name: string; context: number };
}>;

export function personaTopicLearned(
  groupId: string,
  name: string,
  context: number
): PersonaTopicLearnedActionType {
  return { type: PERSONA_TOPIC_LEARNED, payload: { groupId, name, context } };
}

// Create a topic: announces it to the group, and records it
// locally so the composer can immediately offer it.
function createPersonaTopic(
  conversationId: string,
  name: string
): ThunkAction<void, RootStateType, unknown, PersonaTopicLearnedActionType> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (!conversation) {
      return;
    }
    const context = await createTopic(conversation, name);
    const groupId = conversation.get('groupId');
    if (context != null && groupId) {
      dispatch(personaTopicLearned(groupId, name.trim(), context));
    }
  };
}

export type PersonaStatusUpdatedActionType = ReadonlyDeep<{
  type: typeof PERSONA_STATUS_UPDATED;
  payload: PersonaStatus;
}>;

// Read the current persona status and put it in redux for the panel. Called when the
// panel opens and on a timer while it is open — the values move (barrier advances,
// peers reply and unblock sealed sender), so a stale snapshot would mislead.
function refreshPersonaStatus(
  conversationId: string
): ThunkAction<void, RootStateType, unknown, PersonaStatusUpdatedActionType> {
  return (dispatch, getState) => {
    const conversation = window.ConversationController.get(conversationId);
    // Count the persona messages the UI is currently showing. If the timeline has
    // them and the replica has no records, protocol state was lost on restart —
    // the chat history survives but the bulletin does not.
    const { messagesLookup } = getState().conversations;
    const uiPersonaMessageCount = Object.values(messagesLookup).filter(
      message =>
        message.conversationId === conversationId && message.personaEh != null
    ).length;

    dispatch({
      type: PERSONA_STATUS_UPDATED,
      payload: getPersonaStatus(conversation, uiPersonaMessageCount),
    });
  };
}

export type PersonaPseudonymsChangedActionType = ReadonlyDeep<{
  type: typeof PERSONA_PSEUDONYMS_CHANGED;
  payload: { groupId: string; pseudonyms: ReadonlyArray<PersonaPseudonym> };
}>;

export function personaPseudonymsChanged(
  groupId: string,
  pseudonyms: ReadonlyArray<PersonaPseudonym>
): PersonaPseudonymsChangedActionType {
  return { type: PERSONA_PSEUDONYMS_CHANGED, payload: { groupId, pseudonyms } };
}

// Mint a new unlimited pseudonym. Its petname is unknown until its first post — the
// engine only reveals it on the `Emitted` from an actual send.
function createPersonaPseudonym(
  conversationId: string
): ThunkAction<
  // Returns the NEW pseudonym's nonce. The nonce is the identity, so handing it back is
  // what lets the composer select the thing it just created — previously the caller had
  // no way to name it, so the menu kept whatever was selected before and the user had to
  // close the menu, reopen it, and pick the new pseudonym by hand.
  number,
  RootStateType,
  unknown,
  PersonaPseudonymsChangedActionType
> {
  return () => {
    const groupId = window.ConversationController.get(conversationId)?.get('groupId');
    return groupId ? createPseudonym(groupId).nonce : 0;
  };
}

// Send a ZK-PROVED authorship claim linking two of our own pseudonyms.
//
// Takes the two CONTEXTS (for an unlimited pseudonym, its nonce) rather than petnames:
// the names are an OUTPUT of verification, not an input to proving. Passing names in
// would reintroduce exactly the gap this replaced — a claim about whatever the sender
// chose to type. See personasAuthorship.preload.ts.
function sendPersonaAuthorshipClaim(
  conversationId: string,
  contextA: number,
  contextB: number
): ThunkAction<void, RootStateType, unknown, NoopActionType> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      await doSendAuthorshipClaim(conversation, contextA, contextB);
    }
    dispatch(noopAction('sendPersonaAuthorshipClaim'));
  };
}

// Ask for a badge (1=Faculty, 2=Student, 3=Industry). Files a ticket for an admin.
function requestPersonaBadge(
  conversationId: string,
  slot: number
): ThunkAction<
  void,
  RootStateType,
  unknown,
  NoopActionType | ShowToastActionType
> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      const result = await doRequestBadge(conversation, slot);
      dispatch(
        showToast(
          result.ok
            ? { toastType: ToastType.PersonaBadgeRequested }
            : {
                toastType: ToastType.PersonaActionFailed,
                parameters: { reason: result.reason },
              }
        )
      );
    }
    dispatch(noopAction('requestPersonaBadge'));
  };
}

// Approve a pending badge request (admin). The badge lands at the requester's next scan,
// not now — the toast says so, because "approved" and "usable" are not the same moment.
function approvePersonaBadge(
  conversationId: string,
  requestEh: string,
  slot: number
): ThunkAction<
  void,
  RootStateType,
  unknown,
  NoopActionType | ShowToastActionType
> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      const result = await doApproveBadge(conversation, requestEh, slot);
      dispatch(
        showToast(
          result.ok
            ? { toastType: ToastType.PersonaBadgeApproved }
            : {
                toastType: ToastType.PersonaActionFailed,
                parameters: { reason: result.reason },
              }
        )
      );
    }
    dispatch(noopAction('approvePersonaBadge'));
  };
}

// Join the bulletin, so the persona menu's options are actually usable by the time
// someone picks one.
//
// Fire-and-forget by design: the caller is a menu opening, not a user committing to an
// action, so this must never block the menu from rendering or pop a dialog. A failure is
// logged and surfaced by the status panel's "joined" row — and by the specific, named
// refusal each individual action already returns if it is taken before this lands.
function joinPersonaBulletin(
  conversationId: string
): ThunkAction<void, RootStateType, unknown, NoopActionType> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      const joined = await ensurePersonaJoined(conversation);
      if (!joined) {
        log.warn(
          'joinPersonaBulletin: join did not complete; persona actions will refuse ' +
          'until it does'
        );
      }
    }
    dispatch(noopAction('joinPersonaBulletin'));
  };
}

// PROVE badge possession in zero knowledge. Distinct from the composer's badge
// selector, which attaches an unverified label to a post: this publishes a Groth16
// proof over `badge_pred` that is checked by every recipient before it renders.
function provePersonaBadge(
  conversationId: string,
  badge: string
): ThunkAction<
  void,
  RootStateType,
  unknown,
  NoopActionType | ShowToastActionType
> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      const result = await doSendBadgeProof(conversation, badge);
      dispatch(
        showToast(
          result.ok
            ? {
                toastType: ToastType.PersonaBadgeProved,
                parameters: { badge: result.badge },
              }
            : {
                toastType: ToastType.PersonaActionFailed,
                parameters: { reason: result.reason },
              }
        )
      );
    }
    dispatch(noopAction('provePersonaBadge'));
  };
}

// Ask the group's admins to allow this account one more join (personasReset).
function requestPersonaReset(
  conversationId: string
): ThunkAction<void, RootStateType, unknown, NoopActionType | ShowToastActionType> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      const result = await doRequestPersonaReset(conversation, () =>
        runFullPersonaSweep(conversation)
      );
      if (!result.ok) {
        dispatch(
          showToast({
            toastType: ToastType.PersonaActionFailed,
            parameters: { reason: result.reason },
          })
        );
      }
    }
    dispatch(noopAction('requestPersonaReset'));
  };
}

// As an admin: turn personas on in a group that has none (mints its phantom bundle).
function turnOnPersonas(
  conversationId: string
): ThunkAction<void, RootStateType, unknown, NoopActionType | ShowToastActionType> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      const result = await turnOnPersonasInGroup(conversation);
      if (!result.ok) {
        dispatch(
          showToast({
            toastType: ToastType.PersonaActionFailed,
            parameters: { reason: result.reason },
          })
        );
      }
    }
    dispatch(noopAction('turnOnPersonas'));
  };
}

// As an admin: allow a member to join once more.
function approvePersonaReset(
  conversationId: string,
  account: string
): ThunkAction<void, RootStateType, unknown, NoopActionType | ShowToastActionType> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      const result = await doApprovePersonaReset(conversation, account);
      if (!result.ok) {
        dispatch(
          showToast({
            toastType: ToastType.PersonaActionFailed,
            parameters: { reason: result.reason },
          })
        );
      }
    }
    dispatch(noopAction('approvePersonaReset'));
  };
}

function dismissPersonaReset(conversationId: string, account: string): NoopActionType {
  doDismissResetRequest(
    window.ConversationController.get(conversationId)?.get('groupId'),
    account
  );
  return noopAction('dismissPersonaReset');
}

// Take a badge request off this admin's queue. LOCAL ONLY — nothing is broadcast and
// the requester is not told; see `dismissBadgeRequest`. No record is emitted, so this
// needs no conversation and cannot fail on the wire.
function dismissPersonaBadgeRequest(
  conversationId: string,
  requestEh: string
): ThunkAction<
  void,
  RootStateType,
  unknown,
  NoopActionType | ShowToastActionType
> {
  return async dispatch => {
    const ok = doDismissBadgeRequest(
      window.ConversationController.get(conversationId)?.get('groupId'),
      requestEh
    );
    dispatch(
      showToast(
        ok
          ? { toastType: ToastType.PersonaBadgeDismissed }
          : {
              toastType: ToastType.PersonaActionFailed,
              parameters: { reason: 'that request has already been handled' },
            }
      )
    );
    dispatch(noopAction('dismissPersonaBadgeRequest'));
  };
}

// Emit a scan on demand. Scans run on a timer already, but a settled ban only becomes
// visible once a scan has absorbed its callback — so during a demo it is useful to be
// able to say "absorb now" rather than waiting out the interval.
function scanPersonaCallbacksNow(
  conversationId: string
): ThunkAction<
  void,
  RootStateType,
  unknown,
  NoopActionType | ShowToastActionType
> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (!conversation) {
      dispatch(noopAction('scanPersonaCallbacksNow'));
      return;
    }

    // SAY WHAT THE SCAN DID. A scan that absorbs nothing used to be
    // indistinguishable from a scan that absorbed a badge: both left the button
    // looking the same, so "approve, then Scan now, and no badge appears" was
    // unexplainable from the UI — the correct behaviour and a broken one looked
    // identical. Reporting the badge set before and after turns it into a fact.
    const groupId = conversation.get('groupId');
    const before = heldBadges(groupId);

    // Drain, so one press finishes the sweep instead of advancing it by one round.
    // Pressing a button repeatedly until an error stops appearing is not a UI.
    const drained = await drainPersonaScans(conversation);

    const after = heldBadges(groupId);
    const gained = after.filter(b => !before.includes(b));

    if (gained.length > 0) {
      dispatch(
        showToast({
          toastType: ToastType.PersonaScanAbsorbed,
          parameters: { gained: gained.join(', ') },
        })
      );
    } else if (!drained) {
      dispatch(
        showToast({
          toastType: ToastType.PersonaActionFailed,
          parameters: {
            reason: 'the callback sweep did not finish — try Scan now again',
          },
        })
      );
    } else {
      dispatch(showToast({ toastType: ToastType.PersonaScanEmpty }));
    }
    dispatch(noopAction('scanPersonaCallbacksNow'));
  };
}

export const actions = {
  sendPersonaAuthorshipClaim,
  scanPersonaCallbacksNow,
  requestPersonaBadge,
  approvePersonaBadge,
  dismissPersonaBadgeRequest,
  requestPersonaReset,
  turnOnPersonas,
  approvePersonaReset,
  dismissPersonaReset,
  provePersonaBadge,
  joinPersonaBulletin,
  createPersonaPseudonym,
  personaPseudonymsChanged,
  refreshPersonaStatus,
  createPersonaTopic,
  personaTopicLearned,
  addAttachment,
  addPendingAttachment,
  cancelJoinRequest,
  endPoll,
  incrementSendCounter,
  onClearDraft,
  onClearAttachments,
  onCloseLinkPreview,
  onEditorStateChange,
  onTextTooLong,
  processAttachments,
  reactToMessage,
  removeAttachment,
  replaceAttachments,
  resetComposer,
  saveDraftRecordingIfNeeded,
  scrollToPinnedMessage,
  scrollToPollMessage,
  scrollToQuotedMessage,
  sendEditedMessage,
  sendMultiMediaMessage,
  sendPoll,
  sendStickerMessage,
  setComposerFocus,
  setMediaQualitySetting,
  setQuoteByMessageId,
  setQuotedMessage,
  setViewOnce,
  updateComposerDisabled,
};

function incrementSendCounter(conversationId: string): IncrementSendActionType {
  return {
    type: INCREMENT_SEND_COUNTER,
    payload: {
      conversationId,
    },
  };
}

export const useComposerActions = (): BoundActionCreatorsMapObject<
  typeof actions
> => useBoundActions(actions);

function onClearDraft(conversationId: string): StateThunk<NoopActionType> {
  return dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (!conversation) {
      throw new Error('onClearDraft: No conversation found');
    }

    conversation.set({
      draft: '',
      draftBodyRanges: [],
      quotedMessageId: null,
    });

    dispatch(onClearAttachments(conversation.id));
  };
}

function onClearAttachments(conversationId: string): NoopActionType {
  const conversation = window.ConversationController.get(conversationId);
  if (!conversation) {
    throw new Error('onClearAttachments: No conversation found');
  }

  void clearConversationDraftAttachments(
    conversation.id,
    conversation.get('draftAttachments')
  );

  return noopAction('onClearAttachments');
}

function cancelJoinRequest(conversationId: string): NoopActionType {
  const conversation = window.ConversationController.get(conversationId);
  if (!conversation) {
    throw new Error('cancelJoinRequest: No conversation found');
  }

  void longRunningTaskWrapper({
    idForLogging: conversation.idForLogging(),
    name: 'cancelJoinRequest',
    task: async () => conversation.cancelJoinRequest(),
  });

  return noopAction('cancelJoinRequest');
}

function onCloseLinkPreview(conversationId: string): NoopActionType {
  suspendLinkPreviews();
  removeLinkPreview(conversationId);

  return noopAction('onCloseLinkPreview');
}

function onTextTooLong(): ShowToastActionType {
  return {
    type: SHOW_TOAST,
    payload: {
      toastType: ToastType.MessageBodyTooLong,
    },
  };
}

function scrollToQuotedMessage({
  authorId,
  conversationId,
  sentAt,
}: Readonly<{
  authorId: string;
  conversationId: string;
  sentAt: number;
}>): ThunkAction<
  void,
  RootStateType,
  unknown,
  ShowToastActionType | ScrollToMessageActionType
> {
  return async (dispatch, getState) => {
    const messages = await DataReader.getMessagesBySentAt(sentAt);
    const message = messages.find(item =>
      Boolean(
        item.conversationId === conversationId &&
        authorId &&
        getAuthorId(item) === authorId
      )
    );

    if (!message) {
      dispatch({
        type: SHOW_TOAST,
        payload: {
          toastType: ToastType.OriginalMessageNotFound,
        },
      });
      return;
    }

    if (getSelectedConversationId(getState()) !== conversationId) {
      return;
    }

    scrollToMessage(conversationId, message.id)(dispatch, getState, undefined);
  };
}

function scrollToPinnedMessage(
  pinMessage: PinMessageData
): StateThunk<ShowToastActionType | ScrollToMessageActionType> {
  return async (dispatch, getState) => {
    const ourAci = itemStorage.user.getCheckedAci();

    const pinnedMessage = await DataReader.getMessageByAuthorAciAndSentAt(
      ourAci,
      pinMessage.targetAuthorAci,
      pinMessage.targetSentTimestamp,
      { includeEdits: true }
    );

    if (!pinnedMessage) {
      dispatch(
        showToast({
          toastType: ToastType.PinnedMessageNotFound,
        })
      );
      return;
    }

    const selectedConversationId = getSelectedConversationId(getState());

    if (selectedConversationId !== pinnedMessage.conversationId) {
      return;
    }

    dispatch(scrollToMessage(pinnedMessage.conversationId, pinnedMessage.id));
  };
}

function scrollToPollMessage(
  pollAuthorAci: AciString,
  pollTimestamp: number,
  conversationId: string
): ThunkAction<
  void,
  RootStateType,
  unknown,
  ShowToastActionType | ScrollToMessageActionType
> {
  return async (dispatch, getState) => {
    const ourAci = itemStorage.user.getCheckedAci();

    const pollMessage = await DataReader.getMessageByAuthorAciAndSentAt(
      ourAci,
      pollAuthorAci,
      pollTimestamp,
      { includeEdits: true }
    );

    if (!pollMessage || !isPoll(pollMessage)) {
      dispatch({
        type: SHOW_TOAST,
        payload: {
          toastType: ToastType.PollNotFound,
        },
      });
      return;
    }

    if (getSelectedConversationId(getState()) !== conversationId) {
      return;
    }

    scrollToMessage(conversationId, pollMessage.id)(
      dispatch,
      getState,
      undefined
    );
  };
}

export function saveDraftRecordingIfNeeded(
  conversationId: string
): ThunkAction<void, RootStateType, unknown, never> {
  return (dispatch, getState) => {
    const state = getState();

    if (!getIsRecording(state.audioRecorder) || !conversationId) {
      return;
    }

    dispatch(
      completeRecording(conversationId, attachment => {
        dispatch(
          addPendingAttachment(conversationId, { ...attachment, pending: true })
        );
        dispatch(addAttachment(conversationId, attachment));

        const conversation = window.ConversationController.get(conversationId);
        if (!conversation) {
          throw new Error('saveDraftRecordingIfNeeded: No conversation found');
        }

        drop(conversation.updateLastMessage());
      })
    );
  };
}

// oxlint-disable-next-line signal-desktop/enforce-type-alias-readonlydeep
type WithPreSendChecksOptions = Readonly<{
  message?: string;
  voiceNoteAttachment?: InMemoryAttachmentDraftType;
  draftAttachments?: ReadonlyArray<AttachmentDraftType>;
}>;

async function withPreSendChecks(
  conversationId: string,
  options: WithPreSendChecksOptions,
  dispatch: ThunkDispatch<
    RootStateType,
    unknown,
    UpdateComposerDisabledActionType | ShowToastActionType
  >,
  body: () => Promise<void>
): Promise<void> {
  const conversation = window.ConversationController.get(conversationId);
  if (!conversation) {
    throw new Error('withPreSendChecks: No conversation found');
  }

  const sendStart = Date.now();
  const recipientsByConversation = getRecipientsByConversation([
    conversation.attributes,
  ]);

  const { message, voiceNoteAttachment } = options;
  const draftAttachments =
    options.draftAttachments ?? conversation.attributes.draftAttachments;

  try {
    dispatch(updateComposerDisabled(conversationId, true));

    try {
      const sendAnyway = await blockSendUntilConversationsAreVerified(
        recipientsByConversation,
        SafetyNumberChangeSource.MessageSend
      );
      if (!sendAnyway) {
        return;
      }
    } catch (error) {
      log.error(
        'withPreSendChecks block until verified error:',
        Errors.toLogFormat(error)
      );
      return;
    }

    const toast = shouldShowInvalidMessageToast(conversation.attributes);
    if (toast != null) {
      dispatch({
        type: SHOW_TOAST,
        payload: toast,
      });
      return;
    }

    if (
      !message?.length &&
      !hasDraftAttachments(draftAttachments, {
        includePending: false,
      }) &&
      !voiceNoteAttachment
    ) {
      return;
    }

    const sendDelta = Date.now() - sendStart;
    log.info(`withPreSendChecks: Send pre-checks took ${sendDelta}ms`);

    await body();
  } finally {
    dispatch(updateComposerDisabled(conversationId, false));
  }

  conversation.clearTypingTimers();
}

function sendEditedMessage(
  conversationId: string,
  options: WithPreSendChecksOptions & {
    bodyRanges?: DraftBodyRanges;
    targetMessageId: string;
    quoteAuthorAci?: AciString;
    quoteSentAt?: number;
  }
): ThunkAction<
  void,
  RootStateType,
  unknown,
  | UpdateComposerDisabledActionType
  | ShowToastActionType
  | IncrementSendActionType
> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (!conversation) {
      throw new Error('sendEditedMessage: No conversation found');
    }

    const {
      message = '',
      bodyRanges,
      quoteSentAt,
      quoteAuthorAci,
      targetMessageId,
    } = options;

    await withPreSendChecks(conversationId, options, dispatch, async () => {
      try {
        await doSendEditedMessage(conversationId, {
          body: message,
          bodyRanges,
          preview: getLinkPreviewForSend(message),
          quoteAuthorAci,
          quoteSentAt,
          targetMessageId,
        });
        dispatch(incrementSendCounter(conversationId));
      } catch (error) {
        log.error('sendEditedMessage', Errors.toLogFormat(error));
        if (error.toastType) {
          dispatch({
            type: SHOW_TOAST,
            payload: {
              toastType: error.toastType,
            },
          });
        }
      }
    });
  };
}

function sendMultiMediaMessage(
  conversationId: string,
  options: WithPreSendChecksOptions & {
    bodyRanges?: DraftBodyRanges;
    draftAttachments?: ReadonlyArray<AttachmentDraftType>;
    isViewOnce?: boolean;
    timestamp?: number;
    // Personas demo: when set, this message is posted as a persona — routed
    // through the ZK engine and sent as a record (see composePersonaPost).
    personaChoice?: PersonaChoice;
    /** The context (thread) selected in the composer, for display on the message. */
    personaContextName?: string;
  }
): ThunkAction<
  void,
  RootStateType,
  unknown,
  | IncrementSendActionType
  | NoopActionType
  | ResetComposerActionType
  | UpdateComposerDisabledActionType
  | SetQuotedMessageActionType
  | ShowToastActionType
> {
  return async (dispatch, getState) => {
    const conversation = window.ConversationController.get(conversationId);
    if (!conversation) {
      throw new Error('sendMultiMediaMessage: No conversation found');
    }

    const {
      draftAttachments,
      isViewOnce,
      timestamp = Date.now(),
      voiceNoteAttachment,
    } = options;

    const { message = '', bodyRanges } = isViewOnce ? {} : options;

    const state = getState();

    await withPreSendChecks(conversationId, options, dispatch, async () => {
      let attachments: Array<AttachmentType> = [];
      if (voiceNoteAttachment) {
        attachments = [voiceNoteAttachment];
      } else if (draftAttachments) {
        attachments = (
          await Promise.all(draftAttachments.map(resolveAttachmentDraftData))
        ).filter(isNotNil);
      }

      const conversationComposerState = getComposerStateForConversation(
        state.composer,
        conversationId
      );

      const quote = conversationComposerState.quotedMessage?.quote;

      const shouldSendHighQualityAttachments = window.reduxStore
        ? conversationComposerState.shouldSendHighQualityAttachments
        : undefined;

      const sendHQImages =
        shouldSendHighQualityAttachments !== undefined
          ? shouldSendHighQualityAttachments
          : state.items['sent-media-quality'] === 'high';

      // Personas demo: a persona post is emitted as a ZK record here; the model
      // keeps the plaintext for display, and the send path swaps in the record
      // (personaRecordBase64) for the wire.
      let preparePersonaPost:
        | (() => Promise<PreparedPersonaPost | undefined>)
        | undefined;
      if (options.personaChoice && message) {
        // Phase 6: never emit before membership exists. Un-joined, `emitPostPseudo`
        // throws, `composePersonaPost` returns undefined, and we used to fall through
        // and send the text as a PLAIN message under the real account — a silent
        // de-anonymisation. Now we join first, and if that fails we bail out entirely
        // rather than degrade.
        // BANNED MEMBERS CANNOT POST AS A PERSONA in this group.
        //
        // Checked here, before joining or proving, for two reasons. The protocol
        // already enforces it — a banned member's post proof is unsatisfiable — but it
        // fails deep inside proving with an opaque error after seconds of work, and the
        // honest explanation ("an admin flagged your posts") is not recoverable from
        // that error. And refusing early means never falling through to an attributable
        // send, which is the one outcome that would be worse than refusing.
        //
        // Scoped to this group by construction: `banned` lives in the member object for
        // THIS conversation's engine, so a member banned here keeps full persona
        // privileges in every other group.
        const personasGroupId = conversation.get('groupId');
        if (isPersonaBanned(personasGroupId) === true) {
          log.warn(
            'sendMultiMediaMessage: refusing a persona post from a banned member'
          );
          dispatch({
            type: SHOW_TOAST,
            payload: { toastType: ToastType.PersonaBanned },
          });
          return;
        }

        const joined = await ensurePersonaJoined(conversation);
        const catchUpReason = joined
          ? undefined
          : catchUpBlockReason(personasGroupId);
        if (catchUpReason) {
          log.warn('sendMultiMediaMessage: persona post waits for the group state');
          dispatch({
            type: SHOW_TOAST,
            payload: {
              toastType: ToastType.PersonaActionFailed,
              parameters: { reason: catchUpReason },
            },
          });
          return;
        }
        if (!joined) {
          log.error(
            'sendMultiMediaMessage: persona post requested but join failed; refusing to send attributably'
          );
          dispatch({
            type: SHOW_TOAST,
            payload: { toastType: ToastType.Error },
          });
          return;
        }
        // Shown to the member as sending right away, and proved in the background: a post
        // may have to wait for their last action to settle.
        const { personaChoice } = options;
        preparePersonaPost = () =>
          inPostOrder(conversationId, async () => {
            // NEVER SCAN BECAUSE A POST IS ABOUT TO GO OUT: a scan right before a post links
            // the two. Scans run on the public schedule (personasScanSchedule). The one wait
            // here is for a sweep already under way, because the engine refuses a post until
            // it ends.
            if (!(await ensureReadyForPersonaAction(conversation))) {
              log.error(
                'sendMultiMediaMessage: callback sweep would not finish; refusing to send ' +
                'rather than letting the post be rejected mid-flight'
              );
              dispatch(
                showToast({
                  toastType: ToastType.PersonaActionFailed,
                  parameters: {
                    reason:
                      'a callback sweep is unfinished — open Persona status and press Scan now',
                  },
                })
              );
              return undefined;
            }

            if (personaScanRequired(personasGroupId)) {
              log.warn('sendMultiMediaMessage: post limit reached until the next sweep');
              dispatch(
                showToast({
                  toastType: ToastType.PersonaActionFailed,
                  parameters: {
                    reason:
                      'you have reached the post limit — open Persona status and press Scan now',
                  },
                })
              );
              return undefined;
            }
            // The badge to ride alongside this post — only if the member's own zk object
            // actually CONTAINS it. Read at send time rather than baked into the choice so
            // toggling it takes effect on the next message without re-picking a persona.
            //
            // `getSelectedBadgeIfHeld`, never `getSelectedBadge`: the selection is a
            // preference file that survives a reset and was writable by earlier builds, so
            // reading it directly let a merely-REQUESTED badge ride out on every post.
            // Narrowing the composer menu did not fix that, because the menu is not on
            // this path. The gate has to be here, where the claim reaches the wire.
            const personaBadge = getSelectedBadgeIfHeld(personasGroupId);
            // Only a RATE-LIMITED persona has a context; an unlimited pseudonym and an
            // anonymous post deliberately have none, and the absence of the chip is what
            // distinguishes them in the timeline.
            // Whatever context the composer had selected, or the rate-limited
            // persona's own context as a fallback when the UI did not supply one.
            const personaContextName =
              options.personaContextName ??
              (personaChoice.kind === 'rate'
                ? (personasGroupId &&
                    nameForContext(personasGroupId, personaChoice.context)) ||
                  undefined
                : undefined);
            const post = composePersonaPost(
              personasGroupId,
              encodePostText({
                text: message,
                badge: personaBadge,
                contextName: personaContextName,
              }),
              personaChoice
            );
            if (!post) {
              log.error(
                'sendMultiMediaMessage: persona post emit failed; refusing to send attributably'
              );
              dispatch({
                type: SHOW_TOAST,
                payload: { toastType: ToastType.Error },
              });
              return undefined;
            }
            // The engine only tells us a pseudonym's petname when it emits under it, so
            // this is where an unlimited persona's name becomes known.
            if (personaChoice.kind === 'pseudo' && post.persona) {
              if (personasGroupId) {
                recordPetname(personasGroupId, personaChoice.nonce, post.persona);
              }
            }
            const personaFields = {
              persona: post.persona,
              personaFlagged: false,
              personaEh: post.eh,
              // emitPostAnon yields no petname; mark it so our own copy renders
              // "Anonymous" instead of falling through to the phantom contact.
              personaAnonymous: post.persona == null,
              personaRecordBase64: post.personaRecordBase64,
              personaBadge,
              personaContextName,
            };
            log.info(
              `personas: sending post choice=${JSON.stringify(personaChoice)} ` +
              `persona=${personaFields.persona ?? '(anonymous)'} ` +
              `context=${personaFields.personaContextName ?? '(none)'} ` +
              `badge=${personaFields.personaBadge ?? '(none)'}`
            );
            return personaFields;
          });
      }

      try {
        await conversation.enqueueMessageForSend(
          {
            body: message,
            attachments,
            quote,
            preview: getLinkPreviewForSend(message),
            bodyRanges,
            isViewOnce,
            personaAnonymous: options.personaChoice?.kind === 'anon' || undefined,
          },
          {
            sendHQImages,
            timestamp,
            preparePersonaPost,
            // We rely on enqueueMessageForSend to call these within redux's batch
            extraReduxActions: () => {
              conversation.setMarkedUnread(false);
              resetLinkPreview(conversationId);
              drop(
                clearConversationDraftAttachments(
                  conversationId,
                  draftAttachments
                )
              );
              setQuoteByMessageId(conversationId, undefined)(
                dispatch,
                getState,
                undefined
              );
              dispatch(incrementSendCounter(conversationId));

              if (state.items.audioMessage) {
                drop(new Sound({ soundType: SoundType.Whoosh }).play());
              }
            },
          }
        );
      } catch (error) {
        log.error(
          'Error pulling attached files before send',
          Errors.toLogFormat(error)
        );
      }
    });
  };
}

// A member's posts go out in the order they were written, whatever each one waits for.
const personaPostOrder = new Map<string, Promise<unknown>>();

function inPostOrder<T>(
  conversationId: string,
  prepare: () => Promise<T>
): Promise<T> {
  const previous = personaPostOrder.get(conversationId) ?? Promise.resolve();
  const next = previous.then(prepare, prepare);
  personaPostOrder.set(conversationId, next);
  return next;
}

function sendStickerMessage(
  conversationId: string,
  options: {
    packId: string;
    stickerId: number;
  }
): ThunkAction<
  void,
  RootStateType,
  unknown,
  | NoopActionType
  | ShowToastActionType
  | IncrementSendActionType
  | SetQuotedMessageActionType
> {
  return async (dispatch, getState) => {
    const conversation = window.ConversationController.get(conversationId);
    if (!conversation) {
      throw new Error('sendStickerMessage: No conversation found');
    }

    const recipientsByConversation = getRecipientsByConversation([
      conversation.attributes,
    ]);

    try {
      const sendAnyway = await blockSendUntilConversationsAreVerified(
        recipientsByConversation,
        SafetyNumberChangeSource.MessageSend
      );
      if (!sendAnyway) {
        return;
      }

      const toast = shouldShowInvalidMessageToast(conversation.attributes);
      if (toast != null) {
        dispatch({
          type: SHOW_TOAST,
          payload: toast,
        });
        return;
      }

      const isStickerReplySendEnabled = isFeaturedEnabledNoRedux({
        betaKey: 'desktop.stickerReply.send.beta',
        prodKey: 'desktop.stickerReply.send.prod',
      });

      let sendStickerMessageOptions;
      if (isStickerReplySendEnabled) {
        const state = getState();
        const conversationComposerState = getComposerStateForConversation(
          state.composer,
          conversationId
        );
        const quote = conversationComposerState.quotedMessage?.quote;

        const draft = conversation.get('draft');
        const isDraftPresent =
          (draft != null && draft.length > 0) ||
          conversationComposerState.attachments.length > 0;

        sendStickerMessageOptions = {
          quote,
          extraReduxActions: isDraftPresent
            ? undefined
            : () => {
                setQuoteByMessageId(conversationId, undefined)(
                  dispatch,
                  getState,
                  undefined
                );
              },
        };
      } else {
        sendStickerMessageOptions = undefined;
      }

      const { packId, stickerId } = options;
      drop(
        conversation.sendStickerMessage(
          packId,
          stickerId,
          sendStickerMessageOptions
        )
      );
    } catch (error) {
      log.error('clickSend error:', Errors.toLogFormat(error));
    }

    dispatch(noopAction('sendStickerMessage'));
  };
}

function sendPoll(
  conversationId: string,
  poll: PollCreateType,
  // Personas demo: when the composer's persona menu is on, emit a ZK poll record
  // instead of a Signal poll.
  options?: { asPersona?: boolean }
): ThunkAction<
  void,
  RootStateType,
  unknown,
  NoopActionType | ShowToastActionType
> {
  return async dispatch => {
    const conversation = window.ConversationController.get(conversationId);
    if (!conversation) {
      throw new Error('sendPoll: No conversation found');
    }

    const recipientsByConversation = getRecipientsByConversation([
      conversation.attributes,
    ]);

    try {
      const sendAnyway = await blockSendUntilConversationsAreVerified(
        recipientsByConversation,
        SafetyNumberChangeSource.MessageSend
      );
      if (!sendAnyway) {
        return;
      }

      const toast = shouldShowInvalidMessageToast(conversation.attributes);
      if (toast != null) {
        dispatch({
          type: SHOW_TOAST,
          payload: toast,
        });
        return;
      }

      // Personas demo: route through the ZK engine when composing as a persona.
      // `sendPersonaPoll` joins first if needed and fails closed rather than falling
      // back to a Signal poll (which would attribute the poll to the real account).
      if (options?.asPersona && isPersonasEngineEnabled()) {
        const sent = await sendPersonaPoll(conversation, {
          question: poll.question,
          options: [...poll.options],
          kind: 'standard',
        });
        if (!sent) {
          log.error('sendPoll: persona poll failed; not falling back');
          dispatch({
            type: SHOW_TOAST,
            payload: { toastType: ToastType.Error },
          });
        }
        return;
      }

      await enqueuePollCreateForSend(conversation, poll);
    } catch (error) {
      log.error('sendPoll error:', Errors.toLogFormat(error));
    }

    dispatch(noopAction('sendPoll'));
  };
}

// Not cool that we have to pull from ConversationModel here
// but if the current selected conversation isn't the one that we're operating
// on then we won't be able to grab attachments from state so we resort to the
// next in-memory store.
function getAttachmentsFromConversationModel(
  conversationId: string
): ReadonlyArray<AttachmentDraftType> {
  const conversation = window.ConversationController.get(conversationId);
  return conversation?.get('draftAttachments') || [];
}

export function setQuoteByMessageId(
  conversationId: string,
  messageId: string | undefined
): ThunkAction<void, RootStateType, unknown, SetQuotedMessageActionType> {
  return async (dispatch, getState) => {
    const conversation = window.ConversationController.get(conversationId);
    if (!conversation) {
      throw new Error('setQuoteByMessageId: No conversation found');
    }

    const activePanel = getActivePanel(getState());
    if (activePanel != null && messageId != null) {
      // Reset the conversation panels and scroll to the message
      // in case we're inside of a conversation panel like pinned messages
      dispatch(scrollToMessage(conversationId, messageId));
    }

    const draftEditMessage = conversation.get('draftEditMessage');
    // We can remove quotes, but we can't add them
    if (draftEditMessage && messageId) {
      return;
    }
    if (draftEditMessage && draftEditMessage.quote) {
      conversation.set({
        draftEditMessage: {
          ...draftEditMessage,
          quote: undefined,
        },
      });
      dispatch(setComposerFocus(conversation.id));
      return;
    }

    const message = messageId ? await getMessageById(messageId) : undefined;
    const state = getState();
    if (
      !message ||
      !isNormalBubble(message.attributes) ||
      !canReply(
        message.attributes,
        window.ConversationController.getOurConversationIdOrThrow(),
        getConversationSelector(state)
      )
    ) {
      dispatch(setQuotedMessage(conversationId, undefined));
      conversation.set({
        quotedMessageId: undefined,
      });
      await DataWriter.updateConversation(conversation.attributes);
      return;
    }

    const existing = conversation.get('quotedMessageId');
    if (existing !== messageId) {
      const now = Date.now();
      let activeAt = conversation.get('active_at');
      let timestamp = conversation.get('timestamp');

      if (!activeAt && messageId) {
        activeAt = now;
        timestamp = now;
      }

      conversation.set({
        active_at: activeAt,
        draftChanged: true,
        quotedMessageId: messageId,
        timestamp,
      });

      await DataWriter.updateConversation(conversation.attributes);
    }

    const quote = await makeQuote(message.attributes);

    // In case the conversation changed while we were about to set the quote
    if (getSelectedConversationId(getState()) !== conversationId) {
      return;
    }

    dispatch(
      setQuotedMessage(conversationId, {
        conversationId,
        quote,
      })
    );
    dispatch(disableViewOnceIfIneligible(conversationId));

    dispatch(setComposerFocus(conversation.id));
  };
}

function addAttachment(
  conversationId: string,
  attachment: InMemoryAttachmentDraftType
): ThunkAction<void, RootStateType, unknown, ReplaceAttachmentsActionType> {
  return async (dispatch, getState) => {
    // We do async operations first so multiple in-process addAttachments don't stomp on
    //   each other.
    const onDisk = await writeDraftAttachment(attachment);
    const toAdd = { ...onDisk, clientUuid: generateUuid() };

    const state = getState();

    const isSelectedConversation =
      getSelectedConversationId(state) === conversationId;

    const conversationComposerState = getComposerStateForConversation(
      state.composer,
      conversationId
    );

    const draftAttachments = isSelectedConversation
      ? conversationComposerState.attachments
      : getAttachmentsFromConversationModel(conversationId);

    // We expect there to either be a pending draft attachment or an existing
    // attachment that we'll be replacing.
    const hasDraftAttachmentPending = draftAttachments.some(
      draftAttachment => draftAttachment.path === attachment.path
    );

    // User has canceled the draft so we don't need to continue processing
    if (!hasDraftAttachmentPending) {
      await deleteDraftAttachment(toAdd);
      return;
    }

    // Remove any pending attachments that were transcoding
    const index = draftAttachments.findIndex(
      draftAttachment => draftAttachment.path === attachment.path
    );
    let nextAttachments = draftAttachments;
    if (index < 0) {
      log.warn(
        `addAttachment: Failed to find pending attachment with path ${attachment.path}`
      );
      nextAttachments = [...draftAttachments, toAdd];
    } else {
      nextAttachments = replaceIndex(draftAttachments, index, toAdd);
    }

    replaceAttachments(conversationId, nextAttachments)(
      dispatch,
      getState,
      null
    );

    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      conversation.set({
        draftAttachments: nextAttachments,
        draftChanged: true,
      });

      // if the conversation has already unloaded
      if (!isSelectedConversation) {
        const now = Date.now();
        const activeAt = conversation.get('active_at') || now;
        conversation.set({
          active_at: activeAt,
          draftChanged: false,
          draftTimestamp: now,
        });
      }

      await DataWriter.updateConversation(conversation.attributes);
    }
  };
}

function addPendingAttachment(
  conversationId: string,
  pendingAttachment: AttachmentDraftType
): ThunkAction<void, RootStateType, unknown, ReplaceAttachmentsActionType> {
  return (dispatch, getState) => {
    const state = getState();

    const isSelectedConversation =
      getSelectedConversationId(state) === conversationId;

    const conversationComposerState = getComposerStateForConversation(
      state.composer,
      conversationId
    );

    const draftAttachments = isSelectedConversation
      ? conversationComposerState.attachments
      : getAttachmentsFromConversationModel(conversationId);

    const nextAttachments = [...draftAttachments, pendingAttachment];

    dispatch({
      type: REPLACE_ATTACHMENTS,
      payload: {
        conversationId,
        attachments: nextAttachments,
      },
    });

    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      conversation.set({
        draftAttachments: nextAttachments,
        draftChanged: true,
      });
      drop(DataWriter.updateConversation(conversation.attributes));
    }
  };
}

export function setComposerFocus(
  conversationId: string
): ThunkAction<void, RootStateType, unknown, SetFocusActionType> {
  return async (dispatch, getState) => {
    if (getSelectedConversationId(getState()) !== conversationId) {
      return;
    }

    dispatch({
      type: SET_FOCUS,
      payload: {
        conversationId,
      },
    });
  };
}

function onEditorStateChange({
  bodyRanges,
  caretLocation,
  conversationId,
  messageText,
  sendCounter,
}: {
  bodyRanges: DraftBodyRanges;
  caretLocation?: number;
  conversationId: string | undefined;
  messageText: string;
  sendCounter: number;
}): ThunkAction<void, RootStateType, unknown, NoopActionType> {
  return (dispatch, getState) => {
    if (!conversationId) {
      throw new Error(
        'onEditorStateChange: Got falsey conversationId, needs local override'
      );
    }

    const conversation = window.ConversationController.get(conversationId);
    if (!conversation) {
      throw new Error('onEditorStateChange: Unable to find conversation');
    }

    const state = getState().composer.conversations[conversationId];
    if (!state) {
      return;
    }

    if (state.sendCounter !== sendCounter) {
      log.warn(
        `onEditorStateChange: Got update for conversation ${conversation.idForLogging()}`,
        `but sendCounter doesnt match (old: ${state.sendCounter}, new: ${sendCounter})`
      );
      return;
    }

    debouncedSaveDraft(conversationId, messageText, bodyRanges);

    // If we have attachments, don't add link preview
    if (
      hasDraftAttachments(conversation.attributes.draftAttachments, {
        includePending: true,
      }) ||
      Boolean(conversation.attributes.draftEditMessage?.attachmentThumbnail)
    ) {
      return;
    }

    maybeGrabLinkPreview(messageText, LinkPreviewSourceType.Composer, {
      caretLocation,
      conversationId,
    });

    dispatch(noopAction('onEditorStateChange'));
  };
}

function processAttachments({
  conversationId,
  files,
  flags,
}: {
  conversationId: string;
  files: ReadonlyArray<File>;
  flags: number | null;
}): ThunkAction<
  void,
  RootStateType,
  unknown,
  NoopActionType | ShowToastActionType | UpdateComposerDisabledActionType
> {
  return async (dispatch, getState) => {
    if (!files.length) {
      return;
    }

    // If the call came from a conversation we are no longer in we do not
    // update the state.
    if (getSelectedConversationId(getState()) !== conversationId) {
      return;
    }

    const conversation = window.ConversationController.get(conversationId);
    if (!conversation) {
      throw new Error('processAttachments: Unable to find conv');
    }

    const draftEditMessage = conversation.get('draftEditMessage');
    if (draftEditMessage) {
      return;
    }

    const { audioRecorder } = getState();

    if (getIsRecording(audioRecorder)) {
      return;
    }

    if (hasLinkPreviewLoaded()) {
      removeLinkPreview(conversationId);
    }

    let toastToShow: AnyToast | undefined;

    const nextDraftAttachments = (
      conversation.get('draftAttachments') || []
    ).slice();
    const filesToProcess: Array<{
      file: File;
      pendingAttachment: AttachmentDraftType;
    }> = [];
    for (const file of files) {
      const processingResult = preProcessAttachment(file, nextDraftAttachments);
      if (processingResult != null) {
        toastToShow = processingResult;
      } else {
        const pendingAttachment = getPendingAttachment(file);
        if (pendingAttachment) {
          addPendingAttachment(conversationId, pendingAttachment)(
            dispatch,
            getState,
            undefined
          );
          filesToProcess.push({ file, pendingAttachment });
          // we keep a running count of the draft attachments so we can show a
          // toast in case we add too many attachments at once
          nextDraftAttachments.push(pendingAttachment);
        }
      }
    }

    dispatch(updateComposerDisabled(conversationId, true));

    try {
      await Promise.all(
        filesToProcess.map(async ({ file, pendingAttachment }) => {
          try {
            const attachment = await processAttachment(file, {
              generateScreenshot: true,
              flags,
            });
            if (!attachment) {
              removeAttachment(conversationId, pendingAttachment)(
                dispatch,
                getState,
                undefined
              );
              return;
            }
            addAttachment(conversationId, attachment)(
              dispatch,
              getState,
              undefined
            );
          } catch (err) {
            log.error(
              'handleAttachmentsProcessing: failed to process attachment:',
              Errors.toLogFormat(err)
            );
            removeAttachment(conversationId, pendingAttachment)(
              dispatch,
              getState,
              undefined
            );
            toastToShow = { toastType: ToastType.UnableToLoadAttachment };
          }
        })
      );
    } finally {
      dispatch(updateComposerDisabled(conversationId, false));
    }

    if (toastToShow) {
      dispatch({
        type: SHOW_TOAST,
        payload: toastToShow,
      });

      return;
    }

    dispatch(noopAction('processAttachments'));
  };
}

function preProcessAttachment(
  file: File,
  draftAttachments: Array<AttachmentDraftType>
): AnyToast | undefined {
  if (!file) {
    return;
  }

  if (isFileDangerous(file.name)) {
    return { toastType: ToastType.DangerousFileType };
  }

  if (draftAttachments.length >= 32) {
    return { toastType: ToastType.MaxAttachments };
  }

  const haveNonImageOrVideo = draftAttachments.some(
    (attachment: AttachmentDraftType) => {
      return !isImageAttachment(attachment) && !isVideoAttachment(attachment);
    }
  );
  // You can't add another attachment if you already have a non-image staged
  if (haveNonImageOrVideo) {
    return { toastType: ToastType.UnsupportedMultiAttachment };
  }

  const fileType = stringToMIMEType(file.type);
  const imageOrVideo =
    isImageTypeSupported(fileType) || isVideoTypeSupported(fileType);

  // You can't add a non-image attachment if you already have attachments staged
  if (!imageOrVideo && draftAttachments.length > 0) {
    return { toastType: ToastType.CannotMixMultiAndNonMultiAttachments };
  }

  // Putting this after everything else because the other checks are more
  // important to show to the user.
  const sizeLimit = getAttachmentSizeLimit({
    contentType: fileType,
    getRemoteConfigValue,
  });

  if (
    isAttachmentTooLargeToSend({ plaintextSize: file.size, limit: sizeLimit })
  ) {
    return {
      toastType: isVideoAttachment({ contentType: fileType })
        ? ToastType.VideoFileSize
        : ToastType.FileSize,
      parameters: getRenderDetailsForLimit(sizeLimit),
    };
  }

  return undefined;
}

function getPendingAttachment(file: File): AttachmentDraftType | undefined {
  if (!file) {
    return;
  }

  const fileType = stringToMIMEType(file.type);
  const { name: fileName } = path.parse(file.name);

  return {
    contentType: fileType,
    clientUuid: generateUuid(),
    fileName,
    size: file.size,
    path: file.name,
    pending: true,
  };
}

function removeAttachment(
  conversationId: string,
  draft: AttachmentDraftType
): ThunkAction<void, RootStateType, unknown, ReplaceAttachmentsActionType> {
  return async (dispatch, getState) => {
    const state = getState();

    const { attachments } = getComposerStateForConversation(
      state.composer,
      conversationId
    );

    const targetAttachmentIndex = attachments.findIndex(attachment => {
      return (
        (attachment.clientUuid != null &&
          attachment.clientUuid === draft.clientUuid) ||
        (attachment.path != null && attachment.path === draft.path)
      );
    });
    if (targetAttachmentIndex === -1) {
      return;
    }

    const targetAttachment = attachments[targetAttachmentIndex];
    strictAssert(targetAttachment, 'Missing targetAttachment');

    const nextAttachments = attachments
      .slice(0, targetAttachmentIndex)
      .concat(attachments.slice(targetAttachmentIndex + 1));

    const conversation = window.ConversationController.get(conversationId);
    if (conversation) {
      conversation.set({
        draftAttachments: nextAttachments,
        draftChanged: true,
      });
      await DataWriter.updateConversation(conversation.attributes);
    }

    replaceAttachments(conversationId, nextAttachments)(
      dispatch,
      getState,
      null
    );

    if (
      targetAttachment.path &&
      targetAttachment.fileName !== targetAttachment.path
    ) {
      await deleteDraftAttachment(targetAttachment);
    }
  };
}

export function replaceAttachments(
  conversationId: string,
  attachments: ReadonlyArray<AttachmentDraftType>
): ThunkAction<
  void,
  RootStateType,
  unknown,
  ReplaceAttachmentsActionType | SetViewOnceActionType | ShowToastActionType
> {
  return (dispatch, getState) => {
    // If the call came from a conversation we are no longer in we do not
    // update the state.
    if (getSelectedConversationId(getState()) !== conversationId) {
      return;
    }

    if (hasDraftAttachments(attachments, { includePending: true })) {
      removeLinkPreview(conversationId);
    }

    dispatch({
      type: REPLACE_ATTACHMENTS,
      payload: {
        conversationId,
        attachments: attachments.map(resolveDraftAttachmentOnDisk),
      },
    });
    dispatch(setComposerFocus(conversationId));
    dispatch(disableViewOnceIfIneligible(conversationId));
  };
}

function reactToMessage(
  messageId: string,
  reaction: { emoji: Emoji.Variant; remove: boolean }
): ThunkAction<
  void,
  RootStateType,
  unknown,
  NoopActionType | ShowToastActionType
> {
  return async dispatch => {
    const { emoji, remove } = reaction;
    try {
      // Personas demo (Phase 6): RATING, on the gesture people already use.
      //
      // The engine's `emitRate` moves a persona's reputation, and reputation is what
      // a ban poll ultimately acts on — but nothing in the app ever emitted a rate, so
      // reputation could not move at all. Rather than bolt separate up/down buttons
      // onto the bubble, a 👍 / 👎 on a persona post IS the rating: same picker, same
      // keyboard shortcut, same affordance as any other message.
      //
      // Only thumbs are re-routed. Every other emoji stays an ordinary Signal
      // reaction, and a reaction on a non-persona message is untouched.
      const outcome = await maybeSendPersonaRateForReaction({
        messageId,
        emoji,
        remove,
      });
      if (outcome.handled) {
        // A rating is deliberately invisible — it is a proof-carrying record, not a
        // reaction, and rendering it would attach the rater's real account to a
        // pseudonymous act. So the toast IS the feedback; without it the gesture does
        // nothing observable and users reasonably conclude it is broken.
        let payload: AnyToast;
        if (outcome.refusedEmoji) {
          payload = { toastType: ToastType.PersonaReactionBlocked };
        } else if (outcome.refusedSelf) {
          payload = { toastType: ToastType.PersonaSelfRateBlocked };
        } else if (outcome.sent) {
          payload = {
            toastType: ToastType.PersonaRated,
            parameters: { delta: outcome.delta },
          };
        } else {
          // Refused self-rating also lands here; ReactionFailed is the honest answer
          // either way, since no record went out.
          payload = { toastType: ToastType.ReactionFailed };
        }
        dispatch({ type: SHOW_TOAST, payload });
        return;
      }

      await enqueueReactionForSend({
        messageId,
        emoji,
        remove,
      });
      dispatch(noopAction('reactToMessage'));
    } catch (error) {
      log.error(
        'reactToMessage: Error sending reaction',
        error,
        messageId,
        reaction
      );
      dispatch({
        type: SHOW_TOAST,
        payload: {
          toastType: ToastType.ReactionFailed,
        },
      });
    }
  };
}

function endPoll(
  messageId: string
): ThunkAction<
  void,
  RootStateType,
  unknown,
  NoopActionType | ShowToastActionType
> {
  return async dispatch => {
    try {
      await enqueuePollTerminateForSend({ messageId });
      dispatch(noopAction('endPoll'));
    } catch (error) {
      log.error('endPoll: Error sending poll terminate', error, messageId);
      dispatch({
        type: SHOW_TOAST,
        payload: {
          toastType: ToastType.Error,
        },
      });
    }
  };
}

export function resetComposer(conversationId: string): ResetComposerActionType {
  return {
    type: RESET_COMPOSER,
    payload: {
      conversationId,
    },
  };
}
const debouncedSaveDraft = debounce(saveDraft, 100);

function saveDraft(
  conversationId: string,
  messageText: string,
  bodyRanges: DraftBodyRanges
) {
  const conversation = window.ConversationController.get(conversationId);
  if (!conversation) {
    throw new Error('saveDraft: Unable to find conversation');
  }

  const trimmed =
    messageText && messageText.length > 0 ? messageText.trim() : '';

  if (conversation.get('draft') && (!messageText || trimmed.length === 0)) {
    conversation.set({
      draft: null,
      draftChanged: true,
      draftBodyRanges: [],
    });
    drop(DataWriter.updateConversation(conversation.attributes));
    return;
  }

  if (
    messageText !== conversation.get('draft') ||
    !isEqual(bodyRanges, conversation.get('draftBodyRanges'))
  ) {
    const now = Date.now();
    let activeAt = conversation.get('active_at');
    let timestamp = conversation.get('timestamp');

    if (!activeAt) {
      activeAt = now;
      timestamp = now;
    }

    if (messageText.length && conversation.throttledBumpTyping) {
      conversation.throttledBumpTyping();
    }

    conversation.set({
      active_at: activeAt,
      draft: messageText,
      draftBodyRanges: bodyRanges,
      draftChanged: true,
      timestamp,
    });
    drop(DataWriter.updateConversation(conversation.attributes));
  }
}

function updateComposerDisabled(
  conversationId: string,
  value: boolean
): UpdateComposerDisabledActionType {
  return {
    type: UPDATE_COMPOSER_DISABLED,
    payload: {
      conversationId,
      value,
    },
  };
}

function setMediaQualitySetting(
  conversationId: string,
  value: boolean
): SetHighQualitySettingActionType {
  return {
    type: SET_HIGH_QUALITY_SETTING,
    payload: {
      conversationId,
      value,
    },
  };
}

function setQuotedMessage(
  conversationId: string,
  quotedMessage?: QuotedMessageForComposerType
): SetQuotedMessageActionType {
  return {
    type: SET_QUOTED_MESSAGE,
    payload: {
      conversationId,
      quotedMessage,
    },
  };
}

export function setViewOnce({
  conversationId,
  value,
  toastNotify,
}: {
  conversationId: string;
  value: boolean;
  toastNotify: boolean;
}): ThunkAction<
  void,
  RootStateType,
  unknown,
  SetViewOnceActionType | ShowToastActionType
> {
  return async (dispatch, getState) => {
    const composerState = getComposerStateForConversation(
      getState().composer,
      conversationId
    );
    const nextValue =
      value &&
      isViewOnceEligible(
        composerState.attachments,
        Boolean(composerState.quotedMessage)
      );

    if (composerState.isViewOnce !== nextValue) {
      dispatch({
        type: SET_VIEW_ONCE,
        payload: {
          conversationId,
          value: nextValue,
        },
      });

      if (toastNotify) {
        dispatch(
          showToast({
            toastType: nextValue
              ? ToastType.ViewOnceEnabled
              : ToastType.ViewOnceDisabled,
          })
        );
      }
    }

    const conversation = window.ConversationController.get(conversationId);
    if (conversation && conversation.get('draftIsViewOnce') !== nextValue) {
      conversation.set({
        draftIsViewOnce: nextValue,
        draftChanged: true,
      });
      await DataWriter.updateConversation(conversation.attributes);
    }
  };
}

function disableViewOnceIfIneligible(
  conversationId: string,
  toastNotify = true
): ThunkAction<
  void,
  RootStateType,
  unknown,
  SetViewOnceActionType | ShowToastActionType
> {
  return (dispatch, getState) => {
    const composerState = getComposerStateForConversation(
      getState().composer,
      conversationId
    );
    if (
      composerState.isViewOnce &&
      !isViewOnceEligible(
        composerState.attachments,
        Boolean(composerState.quotedMessage)
      )
    ) {
      dispatch(
        setViewOnce({
          conversationId,
          value: false,
          toastNotify,
        })
      );
    }
  };
}

// Reducer

export function getEmptyState(): ComposerStateType {
  return {
    conversations: {},
    personaTopics: {},
    personaPseudonyms: {},
  };
}

function updateComposerState(
  state: Readonly<ComposerStateType>,
  // Every action this helper handles is scoped to a conversation, and it reads
  // `payload.conversationId` unconditionally. PERSONA_TOPIC_LEARNED is app-wide (a
  // topic's context is group-shared, not per-composer) and carries no conversationId,
  // so it is excluded here and handled directly in the reducer instead.
  action: Readonly<
    Exclude<
      ComposerActionType,
      | PersonaTopicLearnedActionType
      | PersonaStatusUpdatedActionType
      | PersonaPseudonymsChangedActionType
    >
  >,
  getNextComposerState: (
    prevState: ComposerStateByConversationType
  ) => Partial<ComposerStateByConversationType>
): ComposerStateType {
  const { conversationId } = action.payload;

  strictAssert(
    conversationId,
    'updateComposerState: no conversationId provided'
  );

  const prevComposerState = getComposerStateForConversation(
    state,
    conversationId
  );

  const nextComposerStateForConversation = assignWithNoUnnecessaryAllocation(
    prevComposerState,
    getNextComposerState(prevComposerState)
  );

  return assignWithNoUnnecessaryAllocation(state, {
    conversations: assignWithNoUnnecessaryAllocation(state.conversations, {
      [conversationId]: nextComposerStateForConversation,
    }),
  });
}

export function reducer(
  state: Readonly<ComposerStateType> = getEmptyState(),
  action: Readonly<ComposerActionType>
): ComposerStateType {
  // Personas demo: fold a topic we created or that a peer announced. Keyed by name,
  // and idempotent — the same announcement can legitimately arrive more than once
  // (a re-announce doubles as a crude backfill for members who missed the first).
  if (action.type === PERSONA_TOPIC_LEARNED) {
    const { groupId, name, context } = action.payload;
    const topics = state.personaTopics[groupId] ?? [];
    if (topics.some(topic => topic.name === name && topic.context === context)) {
      return state;
    }
    return {
      ...state,
      personaTopics: {
        ...state.personaTopics,
        // Upsert: a concurrent-creation tie-break can change a known topic's context.
        [groupId]: [
          ...topics.filter(topic => topic.name !== name),
          { name, context },
        ].sort((a, b) => a.name.localeCompare(b.name)),
      },
    };
  }

  if (action.type === PERSONA_PSEUDONYMS_CHANGED) {
    const { groupId, pseudonyms } = action.payload;
    return {
      ...state,
      personaPseudonyms: { ...state.personaPseudonyms, [groupId]: pseudonyms },
    };
  }

  if (action.type === PERSONA_STATUS_UPDATED) {
    return { ...state, personaStatus: action.payload };
  }

  if (action.type === CONVERSATION_UNLOADED) {
    const nextConversations: Record<string, ComposerStateByConversationType> =
      {};
    for (const [conversationId, conversation] of Object.entries(
      state.conversations
    )) {
      nextConversations[conversationId] = conversation;
    }

    return {
      ...state,
      conversations: nextConversations,
    };
  }

  if (action.type === RESET_COMPOSER) {
    return updateComposerState(state, action, () => ({}));
  }

  if (action.type === REPLACE_ATTACHMENTS) {
    const { attachments } = action.payload;

    return updateComposerState(state, action, () => ({
      attachments,
      ...(attachments.length
        ? {}
        : { shouldSendHighQualityAttachments: undefined }),
    }));
  }

  if (action.type === INCREMENT_SEND_COUNTER) {
    return updateComposerState(state, action, prevState => ({
      sendCounter: prevState.sendCounter + 1,
    }));
  }

  if (action.type === SET_FOCUS) {
    return updateComposerState(state, action, prevState => ({
      focusCounter: prevState.focusCounter + 1,
    }));
  }

  if (action.type === SET_HIGH_QUALITY_SETTING) {
    return updateComposerState(state, action, () => ({
      shouldSendHighQualityAttachments: action.payload.value,
    }));
  }

  if (action.type === SET_QUOTED_MESSAGE) {
    const { quotedMessage } = action.payload;
    return updateComposerState(state, action, () => ({
      quotedMessage,
    }));
  }

  if (action.type === ADD_LINK_PREVIEW) {
    if (action.payload.source !== LinkPreviewSourceType.Composer) {
      return state;
    }

    return updateComposerState(state, action, () => ({
      linkPreviewLoading: true,
      linkPreviewResult: action.payload.linkPreview,
    }));
  }

  if (action.type === REMOVE_LINK_PREVIEW && action.payload.conversationId) {
    return updateComposerState(state, action, () => ({
      linkPreviewLoading: false,
      linkPreviewResult: undefined,
    }));
  }

  if (action.type === ADD_PENDING_ATTACHMENT) {
    return updateComposerState(state, action, prevState => ({
      attachments: [...prevState.attachments, action.payload.attachment],
    }));
  }

  if (action.type === SET_VIEW_ONCE) {
    return updateComposerState(state, action, () => ({
      isViewOnce: action.payload.value,
    }));
  }

  if (action.type === UPDATE_COMPOSER_DISABLED) {
    return updateComposerState(state, action, oldState => ({
      disabledCounter:
        oldState.disabledCounter + (action.payload.value ? 1 : -1),
    }));
  }

  return state;
}
