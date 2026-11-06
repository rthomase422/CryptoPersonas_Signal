// Copyright 2019 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import {
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
} from 'react';
import classNames from 'classnames';
import type { ReadonlyDeep } from 'type-fest';
import type {
  DraftBodyRanges,
  HydratedBodyRangesType,
} from '../types/BodyRange.std.ts';
import type { LocalizerType, ThemeType } from '../types/Util.std.ts';
import type { ErrorDialogAudioRecorderType } from '../types/AudioRecorder.std.ts';
import { RecordingState } from '../types/AudioRecorder.std.ts';
import type { imageToBlurHash } from '../util/imageToBlurHash.dom.ts';
import { dropNull } from '../util/dropNull.std.ts';
import { Spinner } from './Spinner.dom.tsx';
import type {
  InputApi,
  Props as CompositionInputProps,
} from './CompositionInput.dom.tsx';
import { CompositionInput } from './CompositionInput.dom.tsx';
import type { Props as MessageRequestActionsProps } from './conversation/MessageRequestActions.dom.tsx';
import { MessageRequestActions } from './conversation/MessageRequestActions.dom.tsx';
import type { PropsType as GroupV1DisabledActionsPropsType } from './conversation/GroupV1DisabledActions.dom.tsx';
import { GroupV1DisabledActions } from './conversation/GroupV1DisabledActions.dom.tsx';
import type { PropsType as GroupV2PendingApprovalActionsPropsType } from './conversation/GroupV2PendingApprovalActions.dom.tsx';
import { GroupV2PendingApprovalActions } from './conversation/GroupV2PendingApprovalActions.dom.tsx';
import { AnnouncementsOnlyGroupBanner } from './AnnouncementsOnlyGroupBanner.dom.tsx';
import { AttachmentList } from './conversation/AttachmentList.dom.tsx';
import type {
  AttachmentDraftType,
  InMemoryAttachmentDraftType,
} from '../types/Attachment.std.ts';
import { isImageAttachment, isVoiceMessage } from '../util/Attachment.std.ts';
import { isViewOnceEligible } from '../util/viewOnceEligibility.std.ts';
import type { AciString } from '../types/ServiceId.std.ts';
import { AudioCapture } from './conversation/AudioCapture.dom.tsx';
import { CompositionUpload } from './CompositionUpload.dom.tsx';
import type {
  ConversationRemovalStage,
  ConversationType,
  PushPanelForConversationActionType,
  ShowConversationType,
} from '../state/ducks/conversations.preload.ts';
import type { GetConversationByIdType } from '../state/selectors/conversations.dom.ts';
import type { GetSharedGroupNamesType } from '../util/sharedGroupNames.dom.ts';
import type { LinkPreviewForUIType } from '../types/message/LinkPreviews.std.ts';
import { isSameLinkPreview } from '../types/message/LinkPreviews.std.ts';

import { MandatoryProfileSharingActions } from './conversation/MandatoryProfileSharingActions.dom.tsx';
import { MediaQualitySelector } from './MediaQualitySelector.dom.tsx';
import type { Props as QuoteProps } from './conversation/Quote.dom.tsx';
import { Quote } from './conversation/Quote.dom.tsx';
import {
  useAttachFileShortcut,
  useEditLastMessageSent,
} from '../hooks/useKeyboardShortcuts.dom.tsx';
import { MediaEditor } from './MediaEditor.dom.tsx';
import { isImageTypeSupported } from '../util/GoogleChrome.std.ts';
import * as KeyboardLayout from '../services/keyboardLayout.dom.ts';
import { PanelType } from '../types/Panels.std.ts';
import type { SmartCompositionRecordingDraftProps } from '../state/smart/CompositionRecordingDraft.preload.tsx';
import { useEscapeHandling } from '../hooks/useEscapeHandling.dom.ts';
import SelectModeActions from './conversation/SelectModeActions.dom.tsx';
import type { ShowToastAction } from '../state/ducks/toast.preload.ts';
import type { DraftEditMessageType } from '../model-types.d.ts';
import type { ForwardMessagesPayload } from '../state/ducks/globalModals.preload.ts';
import { ForwardMessagesModalType } from './ForwardMessagesModal.dom.tsx';
import { FunPicker } from './fun/FunPicker.dom.tsx';
import type { FunEmojiSelection } from './fun/panels/FunPanelEmojis.dom.tsx';
import type { FunStickerSelection } from './fun/panels/FunPanelStickers.dom.tsx';
import type { FunGifSelection } from './fun/panels/FunPanelGifs.dom.tsx';
import type { SmartDraftGifMessageSendModalProps } from '../state/smart/DraftGifMessageSendModal.preload.tsx';
import { strictAssert } from '../util/assert.std.ts';
import { FunPickerButton } from './fun/FunButton.dom.tsx';
import { AxoDropdownMenu } from '../axo/AxoDropdownMenu.dom.tsx';
import {
  MAX_PSEUDO,
  type PersonaChoice,
} from '../services/personasCarriage.std.ts';
import {
  isPersonaBadge,
  type PersonaBadge,
} from '../services/personasBadges.std.ts';
import { AUTHORSHIP_EXPLANATION } from '../services/personasAuthorship.std.ts';
import { AxoIconButton } from '../axo/AxoIconButton.dom.tsx';
import { tw } from '../axo/tw.dom.tsx';
import type { PollCreateType } from '../types/Polls.dom.ts';
import { PollCreateModal } from './PollCreateModal.dom.tsx';
import { useDocumentKeyDown } from '../hooks/useDocumentKeyDown.dom.ts';
import { hasDraft } from '../util/hasDraft.std.ts';
import type { ContactNameColorType } from '../types/Colors.std.ts';
import type { Emoji } from '../axo/emoji.std.ts';
import { AxoConfirmDialog } from '../axo/AxoConfirmDialog.dom.tsx';
import { AxoDialog } from '../axo/AxoDialog.dom.tsx';
import {
  PersonaStatusDialog,
  type PersonaStatusForUI,
} from './PersonaStatusDialog.dom.tsx';
import {
  personaValueToChoice,
  DEFAULT_RATE_INDEX,
} from '../services/personasComposerChoice.std.ts';
import { requestableBadges } from '../services/personasBadgeRules.std.ts';

export type OwnProps = Readonly<{
  acceptedMessageRequest: boolean | null;
  removalStage: ConversationRemovalStage | null;
  addAttachment: (
    conversationId: string,
    attachment: InMemoryAttachmentDraftType
  ) => unknown;
  announcementsOnly: boolean | null;
  areWeAdmin: boolean | null;
  areWePending: boolean | null;
  areWePendingApproval: boolean | null;
  getSharedGroupNames: GetSharedGroupNamesType;
  cancelRecording: () => unknown;
  completeRecording: (
    conversationId: string,
    onRecordingComplete: (rec: InMemoryAttachmentDraftType) => unknown
  ) => unknown;
  convertDraftBodyRangesIntoHydrated: (
    bodyRanges: DraftBodyRanges | undefined
  ) => HydratedBodyRangesType | undefined;
  conversationId: string;
  conversationSelector: GetConversationByIdType;
  discardEditMessage: (id: string) => unknown;
  draftEditMessage: DraftEditMessageType | null;
  draftAttachments: ReadonlyArray<AttachmentDraftType>;
  errorDialogAudioRecorderType: ErrorDialogAudioRecorderType | null;
  errorRecording: (e: ErrorDialogAudioRecorderType) => unknown;
  focusCounter: number;
  groupAdmins: Array<{
    member: ConversationType;
    labelEmoji: Emoji.Variant | undefined;
    labelString: string | undefined;
  }>;
  groupVersion: 1 | 2 | null;
  i18n: LocalizerType;
  imageToBlurHash: typeof imageToBlurHash;
  isDisabled: boolean;
  isFetchingUUID: boolean | null;
  isFormattingEnabled: boolean;
  isGroupV1AndDisabled: boolean | null;
  isMissingMandatoryProfileSharing: boolean | null;
  isPollSend1to1Enabled: boolean;
  isSignalConversation: boolean;
  isActive: boolean;
  lastEditableMessageId: string | null;
  recordingState: RecordingState;
  memberColors: Map<string, ContactNameColorType>;
  shouldHidePopovers: boolean | null;
  isSmsOnlyOrUnregistered: boolean | null;
  left: boolean | null;
  linkPreviewLoading: boolean;
  linkPreviewResult: LinkPreviewForUIType | null;
  onClearAttachments: (conversationId: string) => unknown;
  onCloseLinkPreview: (conversationId: string) => unknown;
  platform: string;
  textIncludesRecoveryKey: (text: string) => boolean;
  showToast: ShowToastAction;
  processAttachments: (options: {
    conversationId: string;
    files: ReadonlyArray<File>;
    flags: number | null;
  }) => unknown;
  setMediaQualitySetting: (conversationId: string, isHQ: boolean) => unknown;
  sendStickerMessage: (
    id: string,
    opts: { packId: string; stickerId: number }
  ) => unknown;
  sendEditedMessage: (
    conversationId: string,
    options: {
      bodyRanges?: DraftBodyRanges;
      message?: string;
      quoteAuthorAci?: AciString;
      quoteSentAt?: number;
      targetMessageId: string;
    }
  ) => unknown;
  sendMultiMediaMessage: (
    conversationId: string,
    options: {
      draftAttachments?: ReadonlyArray<AttachmentDraftType>;
      bodyRanges?: DraftBodyRanges;
      isViewOnce?: boolean;
      message?: string;
      timestamp?: number;
      voiceNoteAttachment?: InMemoryAttachmentDraftType;
      // Personas demo: post this message as a persona (routed through the engine).
      personaChoice?: PersonaChoice;
      /** The context (thread) selected in the composer, for display on the message. */
      personaContextName?: string;
    }
  ) => unknown;
  sendPoll: (
    conversationId: string,
    poll: PollCreateType,
    // Personas demo: emit this as a ZK poll record rather than a Signal poll.
    options?: { asPersona?: boolean }
  ) => unknown;
  // Personas demo: topics known to this instance, and how to create a new one.
  personaTopics: ReadonlyArray<{ name: string; context: number }>;
  createPersonaTopic: (conversationId: string, name: string) => unknown;
  // Personas demo: the status snapshot and how to refresh it.
  personaStatus: PersonaStatusForUI | undefined;
  /** Badges this member actually holds, from their zk object. */
  heldBadges: ReadonlyArray<string>;
  /** Is this member on the bulletin? A badge request is a record, so it needs this. */
  personaJoined: boolean;
  requestPersonaBadge: (conversationId: string, slot: number) => unknown;
  dismissPersonaBadgeRequest: (requestEh: string) => unknown;
  provePersonaBadge: (conversationId: string, badge: string) => unknown;
  /** Join the bulletin if we have not already. Idempotent. */
  joinPersonaBulletin: (conversationId: string) => unknown;
  approvePersonaBadge: (
    conversationId: string,
    requestEh: string,
    slot: number
  ) => unknown;
  refreshPersonaStatus: (conversationId: string) => unknown;
  // Personas demo: the unlimited pseudonyms this member has minted, and how to mint
  // another. `petname` is undefined until that pseudonym's first post reveals it.
  personaPseudonyms: ReadonlyArray<{
    nonce: number;
    petname?: string;
    index: number;
  }>;
  createPersonaPseudonym: () => unknown;
  // Personas demo: emit a scan on demand rather than waiting for the timer.
  scanPersonaCallbacksNow: (conversationId: string) => unknown;
  // Personas demo: open extra member 1 or 2 (installable build only).
  openPersonasExtraMember?: (slot: 1 | 2) => unknown;
  // Personas demo: the contact-code panel, shown in Persona status.
  personaContactsPanel?: React.ReactNode;
  // Personas demo: admin-approved reset (personasReset).
  requestPersonaReset: (conversationId: string) => unknown;
  // Personas demo: whether this conversation is the app's personas group (one per app
  // for now), and, for an admin of a group with none, turning them on here.
  personaGroupStanding?:
    | { kind: 'this' }
    | { kind: 'none' }
    | { kind: 'full'; names: ReadonlyArray<string> };
  turnOnPersonas?: (conversationId: string) => unknown;
  approvePersonaReset: (conversationId: string, account: string) => unknown;
  dismissPersonaReset: (account: string) => unknown;
  // Personas demo: the instance's UNVERIFIED badge claim, and the setter for it.
  selectedBadge: string | undefined;
  setPersonaBadge: (badge: PersonaBadge | undefined) => unknown;
  // Personas demo: send an UNVERIFIED authorship claim linking two personas.
  sendPersonaAuthorshipClaim: (
    conversationId: string,
    // CONTEXTS (nonces), not names: the proof is built over the context, and the
    // petnames are an output of verification.
    contextA: number,
    contextB: number
  ) => unknown;
  quotedMessageId: string | null;
  quotedMessageProps: null | ReadonlyDeep<
    Omit<
      QuoteProps,
      'i18n' | 'onClick' | 'onClose' | 'withContentAbove' | 'isCompose'
    >
  >;
  quotedMessageAuthorAci: AciString | null;
  quotedMessageSentAt: number | null;

  removeAttachment: (
    conversationId: string,
    attachment: AttachmentDraftType
  ) => unknown;
  scrollToMessage: (conversationId: string, messageId: string) => unknown;
  setComposerFocus: (conversationId: string) => unknown;
  setMessageToEdit: (conversationId: string, messageId: string) => unknown;
  setQuoteByMessageId: (
    conversationId: string,
    messageId: string | undefined
  ) => unknown;
  isViewOnce: boolean;
  setViewOnce: (options: {
    conversationId: string;
    value: boolean;
    toastNotify: boolean;
  }) => unknown;
  shouldSendHighQualityAttachments: boolean;
  showConversation: ShowConversationType;
  warmupRecording: () => void;
  startRecording: (id: string) => unknown;
  terminated: boolean | null;
  theme: ThemeType;
  renderSmartCompositionRecording: () => JSX.Element;
  renderSmartCompositionRecordingDraft: (
    props: SmartCompositionRecordingDraftProps
  ) => JSX.Element | null;
  selectedMessageIds: ReadonlyArray<string> | undefined;
  areSelectedMessagesForwardable: boolean | undefined;
  toggleSelectMode: (on: boolean) => void;
  toggleForwardMessagesModal: (
    payload: ForwardMessagesPayload,
    onForward: () => void
  ) => void;
  toggleDraftGifMessageSendModal: (
    props: SmartDraftGifMessageSendModalProps | null
  ) => void;

  onSelectEmoji: (emojiSelection: FunEmojiSelection) => void;
  emojiSkinToneDefault: Emoji.SkinTone | null;
}>;

export type Props = Pick<
  CompositionInputProps,
  | 'draftText'
  | 'draftBodyRanges'
  | 'getPreferredBadge'
  | 'onEditorStateChange'
  | 'onTextTooLong'
  | 'ourConversationId'
  | 'quotedMessageId'
  | 'sendCounter'
  | 'sortedGroupMembers'
> &
  MessageRequestActionsProps &
  Pick<GroupV1DisabledActionsPropsType, 'showGV2MigrationDialog'> &
  Pick<GroupV2PendingApprovalActionsPropsType, 'cancelJoinRequest'> & {
    pushPanelForConversation: PushPanelForConversationActionType;
  } & OwnProps;

// Personas demo: map the composer's persona-menu selection to a PersonaChoice, or
// undefined for a normal (attributable) message.
//
// Values: 'off' | 'pseudo' | 'anon' | 'rate:N'.
//
//  - 'pseudo' is the UNLIMITED plain pseudonym. It takes no topic, and a member may
//    mint as many as they like, so each send draws a fresh random nonce — that nonce
//    is what makes the next one a different, unlinkable petname.
//  - 'rate:N' is the Nth RATE-LIMITED persona, which IS topic-scoped:
//    persona = H(sk || context || N), N < MAX_PSEUDO. It needs a selected topic to
//    supply the context, so it returns undefined without one rather than silently
//    posting into some default context.
export const CompositionArea = memo(function CompositionArea({
  // Base props
  addAttachment,
  conversationId,
  convertDraftBodyRangesIntoHydrated,
  discardEditMessage,
  draftEditMessage,
  focusCounter,
  i18n,
  imageToBlurHash,
  isDisabled,
  isPollSend1to1Enabled,
  isSignalConversation,
  isActive,
  lastEditableMessageId,
  pushPanelForConversation,
  platform,
  textIncludesRecoveryKey,
  processAttachments,
  removeAttachment,
  sendEditedMessage,
  sendMultiMediaMessage,
  sendPoll,
  personaTopics,
  createPersonaTopic,
  personaStatus,
  heldBadges,
  personaJoined,
  requestPersonaBadge,
  approvePersonaBadge,
  dismissPersonaBadgeRequest,
  provePersonaBadge,
  joinPersonaBulletin,
  refreshPersonaStatus,
  personaPseudonyms,
  createPersonaPseudonym,
  scanPersonaCallbacksNow,
  openPersonasExtraMember,
  personaContactsPanel,
  requestPersonaReset,
  personaGroupStanding = { kind: 'this' },
  turnOnPersonas,
  approvePersonaReset,
  dismissPersonaReset,
  selectedBadge,
  setPersonaBadge,
  sendPersonaAuthorshipClaim,
  setComposerFocus,
  setMessageToEdit,
  setQuoteByMessageId,
  shouldHidePopovers,
  showToast,
  theme,

  // AttachmentList
  draftAttachments,
  onClearAttachments,
  // AudioCapture
  recordingState,
  startRecording,
  warmupRecording,
  // StagedLinkPreview
  linkPreviewLoading,
  linkPreviewResult,
  onCloseLinkPreview,
  // Quote
  quotedMessageId,
  quotedMessageProps,
  quotedMessageAuthorAci,
  quotedMessageSentAt,
  scrollToMessage,
  // View Once
  isViewOnce,
  setViewOnce,
  // MediaQualitySelector
  setMediaQualitySetting,
  shouldSendHighQualityAttachments,
  // CompositionInput
  draftBodyRanges,
  draftText,
  getPreferredBadge,
  isFormattingEnabled,
  onEditorStateChange,
  onTextTooLong,
  ourConversationId,
  sendCounter,
  sortedGroupMembers,
  // FunPicker
  onSelectEmoji,
  emojiSkinToneDefault,
  sendStickerMessage,
  // Message Requests
  acceptedMessageRequest,
  areWePending,
  areWePendingApproval,
  conversationType,
  getSharedGroupNames,
  groupVersion,
  isBlocked,
  isHidden,
  isReported,
  isMissingMandatoryProfileSharing,
  left,
  removalStage,
  acceptConversation,
  blockConversation,
  reportSpam,
  blockAndReportSpam,
  deleteConversation,
  conversationName,
  addedByName,
  // GroupV1 Disabled Actions
  isGroupV1AndDisabled,
  showGV2MigrationDialog,
  // GroupV2
  announcementsOnly,
  areWeAdmin,
  groupAdmins,
  memberColors,
  terminated,
  cancelJoinRequest,
  showConversation,
  // SMS-only contacts
  isSmsOnlyOrUnregistered,
  isFetchingUUID,
  renderSmartCompositionRecording,
  renderSmartCompositionRecordingDraft,
  // Selected messages
  selectedMessageIds,
  areSelectedMessagesForwardable,
  toggleSelectMode,
  toggleForwardMessagesModal,
  // DraftGifMessageSendModal
  toggleDraftGifMessageSendModal,
}: Props): JSX.Element | null {
  const [dirty, setDirty] = useState(false);
  const [large, setLarge] = useState(false);
  // Personas demo: which persona (if any) the next message is posted under. 'off'
  // sends a normal message; 'pseudo' the default persona; 'rate:N' the N-th
  // persona; 'anon' anonymously.
  const [personaValue, setPersonaValue] = useState('off');
  // Personas demo: the topic whose context the rate-limited personas are bound to.
  // Sticky for this conversation until changed, so you set "Union" once and keep
  // posting rather than re-picking it on every message.
  const [personaTopic, setPersonaTopic] = useState<string | undefined>();
  // Choosing a normal message, Anonymous, or an unlimited pseudonym leaves the context.
  // A context only applies to rate-limited personas, and `personaValueToChoice` turns
  // any send made while a context is selected into one — so without this, picking
  // "Anonymous" after posting in a context still sent as rate-limited #1 there, and the
  // only way out was to find "No topic" first.
  const selectTopicFreePersona = useCallback((value: string) => {
    setPersonaValue(value);
    setPersonaTopic(undefined);
  }, []);
  const [isTopicDialogOpen, setIsTopicDialogOpen] = useState(false);
  const [newTopicName, setNewTopicName] = useState('');
  const [isStatusDialogOpen, setIsStatusDialogOpen] = useState(false);
  const [isAuthorshipDialogOpen, setIsAuthorshipDialogOpen] = useState(false);
  const [authorshipFirst, setAuthorshipFirst] = useState('');
  const [authorshipSecond, setAuthorshipSecond] = useState('');

  // Refresh while the panel is open: the barrier advances and peers reply, so a
  // snapshot taken once would show a stale — and possibly reassuring — picture.
  useEffect(() => {
    if (!isStatusDialogOpen) {
      return undefined;
    }
    refreshPersonaStatus(conversationId);
    const interval = setInterval(
      () => refreshPersonaStatus(conversationId),
      2000
    );
    return () => clearInterval(interval);
  }, [isStatusDialogOpen, conversationId, refreshPersonaStatus]);

  const personaTopicContext = personaTopics.find(
    topic => topic.name === personaTopic
  )?.context;
  // Only pseudonyms whose petname is known can be named in a claim: the engine reveals
  // a petname when it first emits under that nonce, so an unused pseudonym has no name
  // for anyone else to recognise.
  // {nonce, petname} pairs, not bare names. The NONCE is the context the proof is
  // built over; the petname is only a label for the picker. Proving from a name would
  // be impossible anyway — the circuit derives the pseudonym from our key and the
  // context, so the name is an OUTPUT of verification rather than an input.
  const namedPseudonyms = useMemo(
    () =>
      personaPseudonyms
        .filter((p): p is typeof p & { petname: string } => Boolean(p.petname))
        .map(p => ({ nonce: p.nonce, petname: p.petname })),
    [personaPseudonyms]
  );

  const [attachmentToEdit, setAttachmentToEdit] = useState<
    AttachmentDraftType | undefined
  >();
  const [isPollModalOpen, setIsPollModalOpen] = useState(false);
  const inputApiRef = useRef<InputApi | null>(null);
  const fileInputRef = useRef<null | HTMLInputElement>(null);
  const photoVideoInputRef = useRef<null | HTMLInputElement>(null);

  const handleForceSend = useCallback(() => {
    setLarge(false);
    if (inputApiRef.current) {
      inputApiRef.current.submit();
    }
  }, [inputApiRef, setLarge]);

  const draftEditMessageBody = draftEditMessage?.body;
  const editedMessageId = draftEditMessage?.targetMessageId;

  let canSend =
    // Text or link preview edited
    dirty ||
    // Quote of edited message changed
    (draftEditMessage != null &&
      dropNull(draftEditMessage.quote?.messageId) !==
        dropNull(quotedMessageId)) ||
    // Link preview of edited message changed
    (draftEditMessage != null &&
      !isSameLinkPreview(linkPreviewResult, draftEditMessage?.preview)) ||
    // Not edit message, but has attachments
    (draftEditMessage == null && draftAttachments.length !== 0);

  // Draft attachments should finish loading
  if (draftAttachments.some(attachment => attachment.pending)) {
    canSend = false;
  }

  const handleSubmit = useCallback(
    (
      message: string,
      bodyRanges: DraftBodyRanges,
      timestamp: number
    ): boolean => {
      if (!canSend) {
        return false;
      }

      if (editedMessageId) {
        sendEditedMessage(conversationId, {
          bodyRanges,
          message,
          // sent timestamp for the quote
          quoteSentAt: quotedMessageSentAt ?? undefined,
          quoteAuthorAci: quotedMessageAuthorAci ?? undefined,
          targetMessageId: editedMessageId,
        });
      } else {
        sendMultiMediaMessage(conversationId, {
          draftAttachments,
          bodyRanges,
          message,
          timestamp,
          isViewOnce,
          personaChoice: personaValueToChoice(
            personaValue,
            personaTopicContext
          ),
          // The selected CONTEXT travels on every persona send, not just a
          // rate-limited one. Context is a conversational thread in the UI — the
          // thing a reader follows — whereas in the protocol it only binds
          // rate-limited personas. Deriving the label from the persona kind meant
          // picking a context and then posting anonymously produced an unlabelled
          // message, which is not what anyone means by "post in this context".
          personaContextName: personaTopic,
        });
      }
      setLarge(false);

      return true;
    },
    [
      personaTopic,
      conversationId,
      canSend,
      draftAttachments,
      editedMessageId,
      isViewOnce,
      personaValue,
      personaTopicContext,
      quotedMessageSentAt,
      quotedMessageAuthorAci,
      sendEditedMessage,
      sendMultiMediaMessage,
      setLarge,
    ]
  );

  const launchAttachmentPicker = useCallback((type?: 'media' | 'file') => {
    const inputRef = type === 'media' ? photoVideoInputRef : fileInputRef;
    const fileInput = inputRef.current;
    if (fileInput) {
      // Setting the value to empty so that onChange always fires in case
      // you add multiple photos.
      fileInput.value = '';
      fileInput.click();
    }
  }, []);

  const launchMediaPicker = useCallback(
    () => launchAttachmentPicker('media'),
    [launchAttachmentPicker]
  );

  const launchFilePicker = useCallback(
    () => launchAttachmentPicker('file'),
    [launchAttachmentPicker]
  );

  const handleOpenPollModal = useCallback(() => {
    setIsPollModalOpen(true);
  }, []);

  const handleClosePollModal = useCallback(() => {
    setIsPollModalOpen(false);
  }, []);

  const handleSendPoll = useCallback(
    (poll: PollCreateType) => {
      // Personas demo: the persona menu governs polls exactly as it governs posts. A
      // poll composed while a persona is selected is emitted as a ZK poll record (so
      // ballots are anonymous and enforced by proof) instead of a Signal poll; with
      // the menu off it is an ordinary Signal poll. Same modal either way.
      sendPoll(conversationId, poll, {
        asPersona:
          personaValueToChoice(personaValue, personaTopicContext) != null,
      });
      handleClosePollModal();
    },
    [
      conversationId,
      personaValue,
      personaTopicContext,
      sendPoll,
      handleClosePollModal,
    ]
  );

  function maybeEditAttachment(attachment: AttachmentDraftType) {
    if (!isImageTypeSupported(attachment.contentType)) {
      return;
    }

    setAttachmentToEdit(attachment);
  }

  const maybeEditMessage = useCallback(() => {
    if (lastEditableMessageId == null) {
      return false;
    }

    const hasDraftMessage = hasDraft({
      draft: draftText,
      draftAttachments,
      quotedMessageId,
    });

    if (hasDraftMessage) {
      return false;
    }

    setMessageToEdit(conversationId, lastEditableMessageId);
    return true;
  }, [
    conversationId,
    draftText,
    draftAttachments,
    quotedMessageId,
    lastEditableMessageId,
    setMessageToEdit,
  ]);

  const attachFileShortcut = useAttachFileShortcut(launchFilePicker);
  const editLastMessageSent = useEditLastMessageSent(maybeEditMessage);
  useDocumentKeyDown(event => {
    const hasFocus = inputApiRef.current?.hasFocus() ?? false;
    if (hasFocus) {
      attachFileShortcut(event);
      editLastMessageSent(event);
    }
  });

  // Focus input on first mount
  useEffect(() => {
    if (inputApiRef.current) {
      inputApiRef.current.focus();
    }
  }, []);

  // Focus input whenever explicitly requested
  const inputFocusedRef = useRef({ focusCounter });
  useEffect(() => {
    if (
      inputApiRef.current &&
      inputFocusedRef.current.focusCounter !== focusCounter
    ) {
      inputApiRef.current.focus();
      inputFocusedRef.current = { focusCounter };
    }
  }, [inputApiRef, focusCounter]);

  const inputResetRef = useRef({ sendCounter, conversationId });
  useEffect(() => {
    if (!inputApiRef.current) {
      return;
    }

    if (
      inputResetRef.current.sendCounter !== sendCounter ||
      inputResetRef.current.conversationId !== conversationId
    ) {
      inputApiRef.current.reset();
      inputResetRef.current = {
        sendCounter,
        conversationId,
      };
    }
  }, [conversationId, sendCounter]);

  // We want to reset the state of Quill only if:
  //
  // - Our other device edits the message (edit history length would change)
  // - User begins editing another message.
  const editDraftContentsSetRef = useRef<{
    targetMessageId: string;
    editHistoryLength: number;
  }>(null);

  useEffect(() => {
    if (!inputApiRef.current) {
      return;
    }

    if (
      editDraftContentsSetRef.current?.targetMessageId !==
        draftEditMessage?.targetMessageId ||
      editDraftContentsSetRef.current?.editHistoryLength !==
        draftEditMessage?.editHistoryLength
    ) {
      inputApiRef.current.setContents(
        draftEditMessageBody ?? '',
        draftBodyRanges ?? undefined,
        true
      );
      editDraftContentsSetRef.current = draftEditMessage
        ? {
            targetMessageId: draftEditMessage.targetMessageId,
            editHistoryLength: draftEditMessage.editHistoryLength,
          }
        : null;
    }
  }, [draftBodyRanges, draftEditMessageBody, draftEditMessage]);

  const setDraftTextRef = useRef<{ conversationId: string }>(null);
  useEffect(() => {
    if (setDraftTextRef.current?.conversationId === conversationId) {
      return;
    }
    try {
      if (!draftText) {
        inputApiRef.current?.setContents('');
        return;
      }

      inputApiRef.current?.setContents(
        draftText,
        draftBodyRanges ?? undefined,
        true
      );
    } finally {
      setDraftTextRef.current = { conversationId };
    }
  }, [conversationId, draftBodyRanges, draftText]);

  const handleToggleLarge = useCallback(() => {
    setLarge(l => !l);
  }, [setLarge]);

  const shouldShowMicrophone =
    !large &&
    draftEditMessage == null &&
    !hasDraft({
      draft: draftText,
      draftAttachments,
      // ignore quotes, can be sent with voice message
      quotedMessageId: null,
    });

  const showMediaQualitySelector = draftAttachments.some(isImageAttachment);

  const showViewOnceToggle = isViewOnceEligible(
    draftAttachments,
    Boolean(quotedMessageId)
  );

  const isViewOnceActive = isViewOnce && showViewOnceToggle;

  let draftEditMessageForInput = draftEditMessage;
  let largeForInput = large;
  let linkPreviewLoadingForInput = linkPreviewLoading;
  let linkPreviewResultForInput = linkPreviewResult;
  let quotedMessageIdForInput = quotedMessageId;

  if (isViewOnceActive) {
    draftEditMessageForInput = null;
    largeForInput = false;
    linkPreviewLoadingForInput = false;
    linkPreviewResultForInput = null;
    quotedMessageIdForInput = null;
  }

  const [funPickerOpen, setFunPickerOpen] = useState(false);

  const handleToggleViewOnce = useCallback(() => {
    setFunPickerOpen(false);
    setViewOnce({
      conversationId,
      value: !isViewOnce,
      toastNotify: true,
    });
  }, [conversationId, isViewOnce, setViewOnce]);

  const handleFunPickerOpenChange = useCallback(
    (open: boolean) => {
      setFunPickerOpen(open);
      if (!open) {
        setComposerFocus(conversationId);
      }
    },
    [conversationId, setComposerFocus]
  );

  const handleFunPickerSelectEmoji = useCallback(
    (emojiSelection: FunEmojiSelection) => {
      if (inputApiRef.current) {
        inputApiRef.current.insertEmoji(emojiSelection);
      }
    },
    []
  );
  const handleFunPickerSelectSticker = useCallback(
    (stickerSelection: FunStickerSelection) => {
      sendStickerMessage(conversationId, {
        packId: stickerSelection.stickerPackId,
        stickerId: stickerSelection.stickerId,
      });
    },
    [sendStickerMessage, conversationId]
  );

  const [confirmGifSelection, setConfirmGifSelection] =
    useState<FunGifSelection | null>(null);

  const handleFunPickerSelectGif = useCallback(
    async (gifSelection: FunGifSelection) => {
      if (draftAttachments.length > 0) {
        setConfirmGifSelection(gifSelection);
      } else {
        toggleDraftGifMessageSendModal({
          conversationId,
          previousComposerDraftText: draftText ?? '',
          previousComposerDraftBodyRanges: draftBodyRanges ?? [],
          gifSelection,
        });
      }
    },
    [
      conversationId,
      toggleDraftGifMessageSendModal,
      draftText,
      draftBodyRanges,
      draftAttachments,
    ]
  );

  const handleConfirmGifSelection = useCallback(() => {
    strictAssert(confirmGifSelection != null, 'Need selected gif to confirm');
    onClearAttachments(conversationId);
    toggleDraftGifMessageSendModal({
      conversationId,
      previousComposerDraftText: draftText ?? '',
      previousComposerDraftBodyRanges: draftBodyRanges ?? [],
      gifSelection: confirmGifSelection,
    });
  }, [
    confirmGifSelection,
    conversationId,
    toggleDraftGifMessageSendModal,
    draftText,
    draftBodyRanges,
    onClearAttachments,
  ]);

  const handleCancelGifSelection = useCallback(() => {
    setConfirmGifSelection(null);
  }, []);

  const handleFunPickerAddStickerPack = useCallback(() => {
    pushPanelForConversation({
      type: PanelType.StickerManager,
    });
  }, [pushPanelForConversation]);

  const mediaQualitySelectorFragment = useMemo(
    () =>
      showMediaQualitySelector ? (
        <div className="CompositionArea__button-cell">
          <MediaQualitySelector
            conversationId={conversationId}
            i18n={i18n}
            isHighQuality={shouldSendHighQualityAttachments}
            onSelectQuality={setMediaQualitySetting}
          />
        </div>
      ) : null,
    [
      conversationId,
      i18n,
      setMediaQualitySetting,
      shouldSendHighQualityAttachments,
      showMediaQualitySelector,
    ]
  );

  const leftHandSideButtonsFragment = (
    <>
      <AxoConfirmDialog.Root
        open={confirmGifSelection != null}
        onOpenChange={handleCancelGifSelection}
        title={i18n('icu:CompositionArea__ConfirmGifSelection__Title')}
        description={i18n('icu:CompositionArea__ConfirmGifSelection__Body')}
      >
        <AxoConfirmDialog.Cancel />
        <AxoConfirmDialog.Action
          variant="strong-primary"
          onClick={handleConfirmGifSelection}
        >
          {i18n('icu:CompositionArea__ConfirmGifSelection__ReplaceButton')}
        </AxoConfirmDialog.Action>
      </AxoConfirmDialog.Root>
      <div
        aria-hidden={isViewOnceActive || undefined}
        className={classNames(
          'CompositionArea__button-cell',
          isViewOnceActive ? tw('invisible') : null
        )}
      >
        <FunPicker
          isReply={Boolean(quotedMessageId)}
          placement="top start"
          open={funPickerOpen}
          onOpenChange={handleFunPickerOpenChange}
          onSelectEmoji={handleFunPickerSelectEmoji}
          onSelectSticker={handleFunPickerSelectSticker}
          onSelectGif={handleFunPickerSelectGif}
          onAddStickerPack={handleFunPickerAddStickerPack}
        >
          <FunPickerButton i18n={i18n} />
        </FunPicker>
      </div>
      {mediaQualitySelectorFragment}
    </>
  );

  const micButtonFragment = shouldShowMicrophone ? (
    <div className="CompositionArea__button-cell">
      <AudioCapture
        conversationId={conversationId}
        draftAttachments={draftAttachments}
        i18n={i18n}
        showToast={showToast}
        warmupRecording={warmupRecording}
        startRecording={startRecording}
      />
    </div>
  ) : null;

  const editMessageFragment = draftEditMessage ? (
    <>
      {large && <div className="CompositionArea__placeholder" />}
      <div className="CompositionArea__button-cell CompositionArea__button-edit">
        <button
          aria-label={i18n('icu:CompositionArea__edit-action--discard')}
          className="CompositionArea__edit-button CompositionArea__edit-button--discard"
          onClick={() => discardEditMessage(conversationId)}
          type="button"
        />
        <button
          aria-label={i18n('icu:CompositionArea__edit-action--send')}
          className="CompositionArea__edit-button CompositionArea__edit-button--accept"
          disabled={!canSend}
          onClick={() => inputApiRef.current?.submit()}
          type="button"
        />
      </div>
    </>
  ) : null;

  const isRecording = recordingState === RecordingState.Recording;
  const actionSlotClassName = tw(
    'flex size-8 shrink-0 items-center justify-center'
  );

  const composerAddMenuButton =
    draftEditMessage || linkPreviewResult || isRecording ? null : (
      <div className="CompositionArea__button-cell">
        <AxoDropdownMenu.Root>
          <div className={actionSlotClassName}>
            <AxoDropdownMenu.Trigger>
              <AxoIconButton.Root
                variant="implied-secondary"
                size="md"
                label={i18n('icu:CompositionArea--attach-plus')}
                tooltip={false}
                symbol="plus"
              />
            </AxoDropdownMenu.Trigger>
          </div>
          <AxoDropdownMenu.Content>
            <AxoDropdownMenu.Item symbol="photo" onSelect={launchMediaPicker}>
              {i18n('icu:CompositionArea__AttachMenu__PhotosAndVideos')}
            </AxoDropdownMenu.Item>
            <AxoDropdownMenu.Item symbol="file" onSelect={launchFilePicker}>
              {i18n('icu:CompositionArea__AttachMenu__File')}
            </AxoDropdownMenu.Item>
            {(conversationType === 'group' || isPollSend1to1Enabled) && (
              <AxoDropdownMenu.Item
                symbol="poll"
                onSelect={handleOpenPollModal}
              >
                {i18n('icu:CompositionArea__AttachMenu__Poll')}
              </AxoDropdownMenu.Item>
            )}
          </AxoDropdownMenu.Content>
        </AxoDropdownMenu.Root>
      </div>
    );

  // Personas demo: pick the persona (or normal message) the next post is sent
  // under, and the topic that scopes the rate-limited ones. Highlighted when a
  // persona is active.
  // Personas work in groups only.
  const personaMenuButton =
    conversationType !== 'group' ? null : (
      <div className="CompositionArea__button-cell">
        {/* JOIN ON OPEN. Membership is a prerequisite for almost everything in this menu
          — a pseudonymous post, a badge request, a rating, a badge proof are all member
          records — and until now the only thing that joined was sending a message. That
          made the menu actively misleading: every option was visible and most of them
          failed with "this member is not on the bulletin yet", which reads as a broken
          build rather than as a sequencing requirement.

          Opening the menu is the natural moment. The person has signalled intent to do
          something with personas, and joining takes one attributable record plus a
          sealed-sender warm-up — both of which the first post would have sent anyway,
          so nothing is sent here that was not already implied.

          `ensurePersonaJoined` is idempotent and de-duplicates concurrent callers, so
          re-opening the menu costs nothing after the first time. */}
        <AxoDropdownMenu.Root
          onOpenChange={open => {
            if (open && personaGroupStanding.kind === 'this') {
              joinPersonaBulletin(conversationId);
            }
          }}
        >
          <div className={actionSlotClassName}>
            <AxoDropdownMenu.Trigger>
              <AxoIconButton.Root
                variant={
                  personaValue === 'off'
                    ? 'implied-secondary'
                    : 'strong-primary'
                }
                size="md"
                label="Persona"
                tooltip={false}
                symbol="person-circle"
              />
            </AxoDropdownMenu.Trigger>
          </div>
          <AxoDropdownMenu.Content>
            {personaGroupStanding.kind === 'full' && (
              <AxoDropdownMenu.Label>
                {`Personas are already on in ${personaGroupStanding.names.length} groups ` +
                  `for this account (${personaGroupStanding.names.join(', ')}), the most ` +
                  'there can be for now.'}
              </AxoDropdownMenu.Label>
            )}
            {personaGroupStanding.kind === 'none' && (
              <>
                <AxoDropdownMenu.Label>
                  {areWeAdmin
                    ? 'Personas are not on in this group yet. Turning them on gives the ' +
                      'group its own anonymous identity; only one admin should do it.'
                    : 'Personas are not on in this group yet. A group admin can turn them on.'}
                </AxoDropdownMenu.Label>
                {areWeAdmin && turnOnPersonas != null && (
                  <AxoDropdownMenu.Item
                    symbol="person-circle"
                    onSelect={() => turnOnPersonas(conversationId)}
                  >
                    Turn on personas in this group
                  </AxoDropdownMenu.Item>
                )}
              </>
            )}
            {personaGroupStanding.kind === 'this' && (
              <>
                {/* First, not last: the status panel is where extra members, resets,
                    badge and reset approvals and "am I banned?" live, and at the bottom of
                    a long menu it had to be scrolled to. */}
                <AxoDropdownMenu.Item
                  symbol="info"
                  onSelect={() => setIsStatusDialogOpen(true)}
                >
                  Persona status…
                </AxoDropdownMenu.Item>
                <AxoDropdownMenu.Separator />
                {/* Membership, stated at the top rather than discovered through a failure.
              Shown only while NOT joined: a permanent "joined" banner would be noise,
              but its absence while joining explains why an option may refuse for a
              second or two. The join is kicked off by opening this menu. */}
                {!personaJoined && (
                  <AxoDropdownMenu.Label>
                    Joining the bulletin… anonymous and pseudonymous options
                    need this.
                  </AxoDropdownMenu.Label>
                )}
                <AxoDropdownMenu.RadioGroup
                  value={personaValue}
                  onValueChange={selectTopicFreePersona}
                >
                  <AxoDropdownMenu.RadioItem value="off">
                    Normal message
                  </AxoDropdownMenu.RadioItem>
                  <AxoDropdownMenu.RadioItem value="anon">
                    Anonymous
                  </AxoDropdownMenu.RadioItem>
                </AxoDropdownMenu.RadioGroup>

                <AxoDropdownMenu.Separator />

                {/* Unlimited pseudonyms: topic-free, and a member may mint as many as they
              like. Each is a stable identity (the nonce), so selecting one here posts
              AGAIN as that persona rather than as a new stranger. A pseudonym's
              petname is only known once it has posted — the engine reveals it on
              emit, there is no way to ask for it in advance. */}
                <AxoDropdownMenu.Label>
                  Pseudonyms · unlimited, no context
                </AxoDropdownMenu.Label>
                <AxoDropdownMenu.RadioGroup
                  value={personaValue}
                  onValueChange={selectTopicFreePersona}
                >
                  {personaPseudonyms.map(pseudonym => (
                    <AxoDropdownMenu.RadioItem
                      key={pseudonym.nonce}
                      value={`pseudo:${pseudonym.nonce}`}
                    >
                      {pseudonym.petname != null
                        ? `~${pseudonym.petname}`
                        : `Pseudonym ${pseudonym.index} · unused`}
                    </AxoDropdownMenu.RadioItem>
                  ))}
                </AxoDropdownMenu.RadioGroup>
                <AxoDropdownMenu.Item
                  symbol="plus"
                  onSelect={() => {
                    // SELECT WHAT WE JUST MADE. Minting a pseudonym and leaving the previous
                    // one selected meant the only way to use it was to close the menu, reopen
                    // it and pick it by hand — and the obvious reading of "New pseudonym" is
                    // that you are now posting as it.
                    //
                    // `createPersonaPseudonym` returns the new nonce (the nonce IS the
                    // identity). Guarded on `typeof` rather than assumed: this value comes
                    // back through redux's dispatch, so a non-number here means the action
                    // chain changed shape, and selecting `pseudo:undefined` would produce an
                    // unsatisfiable choice that silently sends a plain, attributable message.
                    const nonce = createPersonaPseudonym();
                    if (typeof nonce === 'number' && Number.isFinite(nonce)) {
                      setPersonaValue(`pseudo:${nonce}`);
                      // An unlimited pseudonym has no context, so leaving a context selected
                      // would re-coerce the next send back to a rate-limited persona and
                      // discard the pseudonym we just switched to.
                      setPersonaTopic(undefined);
                    }
                  }}
                >
                  New pseudonym
                </AxoDropdownMenu.Item>

                <AxoDropdownMenu.Separator />

                {/* Rate-limited personas are bound to a CONTEXT, so they are only selectable
              once a context is chosen. At most MAX_PSEUDO of them per context, which is
              the whole point: an unlimited pseudonym costs a member nothing, while these
              are a scarce resource within a context, so a reputation attached to one
              actually means something. The label carries that distinction because the
              two kinds are otherwise indistinguishable in a menu. */}
                <AxoDropdownMenu.Label>
                  {personaTopic != null
                    ? `Rate-limited · max ${MAX_PSEUDO} in “${personaTopic}”`
                    : `Rate-limited · max ${MAX_PSEUDO} per context — pick a context below`}
                </AxoDropdownMenu.Label>
                <AxoDropdownMenu.RadioGroup
                  value={personaValue}
                  onValueChange={setPersonaValue}
                >
                  {Array.from({ length: MAX_PSEUDO }, (_unused, index) => (
                    <AxoDropdownMenu.RadioItem
                      // oxlint-disable-next-line react/no-array-index-key
                      key={`persona-rate-${index}`}
                      value={`rate:${index}`}
                      disabled={personaTopicContext == null}
                    >
                      {personaTopic != null
                        ? `#${index + 1} in “${personaTopic}”`
                        : `#${index + 1}`}
                    </AxoDropdownMenu.RadioItem>
                  ))}
                </AxoDropdownMenu.RadioGroup>

                <AxoDropdownMenu.Separator />

                {/* Say out loud that choosing a context CHANGES the persona. Selecting one
              forces a rate-limited pseudonym for that context (defaulting to #1),
              because a context only binds in-circuit for a rate-limited persona — an
              anonymous post carrying a context label is a claim nothing backs. Silent
              coercion of an identity choice would be unacceptable, so it is stated
              here rather than left to be discovered. */}
                <AxoDropdownMenu.Label>
                  {personaTopic != null
                    ? `Context · posting as rate-limited #${
                        personaValue.startsWith('rate:')
                          ? Number(personaValue.slice('rate:'.length)) + 1
                          : DEFAULT_RATE_INDEX + 1
                      } in “${personaTopic}”`
                    : 'Context — choosing one posts as a rate-limited pseudonym'}
                </AxoDropdownMenu.Label>
                <AxoDropdownMenu.RadioGroup
                  value={personaTopic ?? ''}
                  onValueChange={value => {
                    const name = value || undefined;
                    setPersonaTopic(name);
                    // MOVE THE RADIO SELECTION, not just the derived choice.
                    //
                    // `personaValueToChoice` already coerces to a rate-limited pseudonym when
                    // a context is set, so sends were correct — but the menu still showed the
                    // check mark next to whatever was picked before (often "Anonymous"), so
                    // the UI claimed one identity while the message used another. For an
                    // identity control that is not a cosmetic bug, and it is why this looked
                    // like the default "not working": there was no way to see that it had.
                    //
                    // Selecting the radio makes the check mark land on #1 and keeps the menu
                    // and the wire in agreement.
                    if (name != null && !personaValue.startsWith('rate:')) {
                      setPersonaValue(`rate:${DEFAULT_RATE_INDEX}`);
                    }
                    // Clearing the context leaves a `rate:` selection unsatisfiable — there
                    // is no context for the rate limit to bind to — and an unsatisfiable
                    // choice makes the duck send a PLAIN, attributable message. Fall back to
                    // anonymous rather than silently de-anonymizing the next post.
                    if (name == null && personaValue.startsWith('rate:')) {
                      setPersonaValue('anon');
                    }
                  }}
                >
                  <AxoDropdownMenu.RadioItem value="">
                    No topic
                  </AxoDropdownMenu.RadioItem>
                  {personaTopics.map(topic => (
                    <AxoDropdownMenu.RadioItem
                      key={topic.name}
                      value={topic.name}
                    >
                      {topic.name}
                    </AxoDropdownMenu.RadioItem>
                  ))}
                </AxoDropdownMenu.RadioGroup>
                {/* Topic creation is ATTRIBUTABLE (the announcement goes out under the
              real account), so gating it on Signal's admin role is meaningful in a
              way that gating an anonymous action could never be. Still a client-side
              convenience rather than enforcement — see the status panel. */}
                <AxoDropdownMenu.Item
                  symbol="plus"
                  disabled={!areWeAdmin}
                  onSelect={() => {
                    setNewTopicName('');
                    setIsTopicDialogOpen(true);
                  }}
                >
                  {areWeAdmin ? 'New context…' : 'New context… (admins only)'}
                </AxoDropdownMenu.Item>

                <AxoDropdownMenu.Separator />

                {/* BADGES, now credentials rather than labels.
              The selector offers ONLY badges this member actually holds in their zk
              object — a badge you hold can be proved, and one you do not cannot be
              attached at all. That is the whole difference from the old behaviour,
              where any label could be typed on any message. */}
                <AxoDropdownMenu.Sub>
                  <AxoDropdownMenu.SubTrigger symbol="person-circle">
                    {/* The label reflects what will actually be SENT, not what is stored.
                  A selection the member no longer holds (or never held — the
                  preference file outlives a reset) is dropped by the send path, so
                  showing it here would promise a badge the post will not carry. */}
                    {heldBadges.length === 0
                      ? 'Badge: none held'
                      : `Badge: ${
                          selectedBadge != null &&
                          heldBadges.includes(selectedBadge)
                            ? selectedBadge
                            : 'none'
                        }`}
                  </AxoDropdownMenu.SubTrigger>
                  <AxoDropdownMenu.SubContent>
                    {heldBadges.length === 0 ? (
                      <AxoDropdownMenu.Label>
                        You hold no approved badges yet — request one below.
                      </AxoDropdownMenu.Label>
                    ) : (
                      <AxoDropdownMenu.RadioGroup
                        value={selectedBadge ?? ''}
                        onValueChange={value =>
                          setPersonaBadge(
                            isPersonaBadge(value) ? value : undefined
                          )
                        }
                      >
                        <AxoDropdownMenu.RadioItem value="">
                          None
                        </AxoDropdownMenu.RadioItem>
                        {heldBadges.map(label => (
                          <AxoDropdownMenu.RadioItem key={label} value={label}>
                            {label}
                          </AxoDropdownMenu.RadioItem>
                        ))}
                      </AxoDropdownMenu.RadioGroup>
                    )}
                  </AxoDropdownMenu.SubContent>
                </AxoDropdownMenu.Sub>

                {/* REQUEST a badge. The first thing a member without one sees, since the
              selector above is empty until an admin approves something.
              Blocked options stay VISIBLE but disabled with the reason: the circuit
              silently declines a conflicting assignment, so "why can I not ask for
              Faculty?" has to be answerable here rather than discovered after an
              approval that quietly did nothing. */}
                <AxoDropdownMenu.Sub>
                  <AxoDropdownMenu.SubTrigger symbol="plus">
                    Request badge…
                  </AxoDropdownMenu.SubTrigger>
                  <AxoDropdownMenu.SubContent>
                    {/* NOT gated on membership. `requestBadge` joins first if it has to, the
                  same way posting and rating always have, so there is nothing for the
                  member to do in the right order. An earlier version of this menu
                  disabled itself with "send one ordinary message first" — which was an
                  accurate description of a bug being presented as a requirement. */}
                    <AxoDropdownMenu.Label>
                      {personaJoined
                        ? "Needs a group admin's approval"
                        : "Needs a group admin's approval. Joins the bulletin first, so the request may take a moment."}
                    </AxoDropdownMenu.Label>
                    {requestableBadges(heldBadges).map(
                      ({ slot, name, blockedReason }) => (
                        <AxoDropdownMenu.Item
                          key={slot}
                          disabled={blockedReason != null}
                          onSelect={() =>
                            requestPersonaBadge(conversationId, slot)
                          }
                        >
                          {blockedReason != null
                            ? `${name} — ${blockedReason}`
                            : name}
                        </AxoDropdownMenu.Item>
                      )
                    )}
                  </AxoDropdownMenu.SubContent>
                </AxoDropdownMenu.Sub>

                <AxoDropdownMenu.Separator />

                {/* ZK-PROVED authorship claim. Needs two NAMED personas: the proof is built
              over each pseudonym's nonce, but the picker has to show something a human
              recognises, and a pseudonym has no petname until it has posted once (the
              engine reveals the name when it first emits under that nonce). So this
              stays disabled until two of this instance's pseudonyms have posted. */}
                <AxoDropdownMenu.Item
                  symbol="link"
                  disabled={namedPseudonyms.length < 2}
                  onSelect={() => setIsAuthorshipDialogOpen(true)}
                >
                  {/* No longer "(unverified)": the claim carries a Groth16 proof over
                authorship_pred and recipients verify it before rendering. The label was
                the last place in the UI still describing the old behaviour. */}
                  {namedPseudonyms.length < 2
                    ? 'Prove authorship… (needs 2 posted personas)'
                    : 'Prove authorship…'}
                </AxoDropdownMenu.Item>

                {/* ZK-PROVED badge possession — the counterpart to "Prove authorship".
              Offers only badges actually HELD, because the proof is unsatisfiable
              otherwise: there is no witness for a badge that is not in the object. So
              an empty list here is not a UI limitation, it is the security property,
              and the disabled label says what to do about it.
              Note this is a DIFFERENT action from the badge selector above. That
              attaches a decorative label to a post; this publishes a proof. Both exist
              because the gap between them is the thing worth demonstrating. */}
                <AxoDropdownMenu.Sub>
                  <AxoDropdownMenu.SubTrigger symbol="check-circle">
                    {heldBadges.length === 0
                      ? 'Prove badge… (none held)'
                      : 'Prove badge…'}
                  </AxoDropdownMenu.SubTrigger>
                  <AxoDropdownMenu.SubContent>
                    {heldBadges.length === 0 ? (
                      <AxoDropdownMenu.Label>
                        No approved badges yet — request one above, then Scan
                        now.
                      </AxoDropdownMenu.Label>
                    ) : (
                      <>
                        <AxoDropdownMenu.Label>
                          Proves you hold it, without revealing who you are
                        </AxoDropdownMenu.Label>
                        {heldBadges.map(label => (
                          <AxoDropdownMenu.Item
                            key={label}
                            onSelect={() =>
                              provePersonaBadge(conversationId, label)
                            }
                          >
                            {label}
                          </AxoDropdownMenu.Item>
                        ))}
                      </>
                    )}
                  </AxoDropdownMenu.SubContent>
                </AxoDropdownMenu.Sub>
              </>
            )}
          </AxoDropdownMenu.Content>
        </AxoDropdownMenu.Root>
      </div>
    );

  // Creating a topic announces it to the group, so every
  // member binds the same context for this topic name.
  const handleCreateTopic = useCallback(() => {
    const name = newTopicName.trim();
    if (name) {
      createPersonaTopic(conversationId, name);
      setPersonaTopic(name);
      // Same rule as picking an existing context from the menu: a context implies a
      // rate-limited pseudonym, so select #1 unless one is already chosen. Creating a
      // context is the most common way to end up in one, so omitting it here would
      // leave the main path showing the wrong check mark.
      if (!personaValue.startsWith('rate:')) {
        setPersonaValue(`rate:${DEFAULT_RATE_INDEX}`);
      }
    }
    setIsTopicDialogOpen(false);
  }, [conversationId, createPersonaTopic, newTopicName, personaValue]);

  const personaTopicDialog = isTopicDialogOpen ? (
    <AxoDialog.Root open onOpenChange={setIsTopicDialogOpen}>
      <AxoDialog.Content size="sm" escape="cancel-is-destructive">
        <AxoDialog.Header>
          <AxoDialog.Title>New context</AxoDialog.Title>
          <AxoDialog.Close />
        </AxoDialog.Header>
        <AxoDialog.Body>
          <input
            type="text"
            placeholder="Context name (e.g. Union)"
            value={newTopicName}
            onChange={event => setNewTopicName(event.target.value)}
            className={tw(
              'border-primary bg-secondary w-full rounded-lg border px-3 py-2 type-body-medium text-primary'
            )}
          />
        </AxoDialog.Body>
        <AxoDialog.Footer>
          <AxoDialog.Actions>
            <AxoDialog.Action
              variant="strong-secondary"
              onClick={() => setIsTopicDialogOpen(false)}
            >
              {i18n('icu:cancel')}
            </AxoDialog.Action>
            <AxoDialog.Action
              variant="strong-primary"
              onClick={handleCreateTopic}
              disabled={newTopicName.trim().length === 0}
            >
              Create
            </AxoDialog.Action>
          </AxoDialog.Actions>
        </AxoDialog.Footer>
      </AxoDialog.Content>
    </AxoDialog.Root>
  ) : null;

  // The authorship claim dialog. Two pickers and a permanent warning: the warning is
  // not a footnote here because the person about to SEND this should understand that it
  // proves nothing before they say it, not after.
  const personaAuthorshipDialog = isAuthorshipDialogOpen ? (
    <AxoDialog.Root open onOpenChange={setIsAuthorshipDialogOpen}>
      <AxoDialog.Content size="sm" escape="cancel-is-destructive">
        <AxoDialog.Header>
          <AxoDialog.Title>Claim authorship</AxoDialog.Title>
          <AxoDialog.Close />
        </AxoDialog.Header>
        <AxoDialog.Body>
          <div className={tw('flex flex-col gap-3')}>
            <div className={tw('text-secondary type-body-small')}>
              {AUTHORSHIP_EXPLANATION}
            </div>
            <select
              value={authorshipFirst}
              onChange={event => setAuthorshipFirst(event.target.value)}
              className={tw(
                'border-primary bg-secondary w-full rounded-lg border px-3 py-2 type-body-medium text-primary'
              )}
            >
              <option value="">First persona…</option>
              {namedPseudonyms.map(p => (
                <option key={p.nonce} value={String(p.nonce)}>
                  {p.petname}
                </option>
              ))}
            </select>
            <select
              value={authorshipSecond}
              onChange={event => setAuthorshipSecond(event.target.value)}
              className={tw(
                'border-primary bg-secondary w-full rounded-lg border px-3 py-2 type-body-medium text-primary'
              )}
            >
              <option value="">Second persona…</option>
              {namedPseudonyms
                .filter(p => String(p.nonce) !== authorshipFirst)
                .map(p => (
                  <option key={p.nonce} value={String(p.nonce)}>
                    {p.petname}
                  </option>
                ))}
            </select>
          </div>
        </AxoDialog.Body>
        <AxoDialog.Footer>
          <AxoDialog.Actions>
            <AxoDialog.Action
              variant="strong-secondary"
              onClick={() => setIsAuthorshipDialogOpen(false)}
            >
              {i18n('icu:cancel')}
            </AxoDialog.Action>
            <AxoDialog.Action
              variant="strong-primary"
              disabled={
                !authorshipFirst ||
                !authorshipSecond ||
                authorshipFirst === authorshipSecond
              }
              onClick={() => {
                sendPersonaAuthorshipClaim(
                  conversationId,
                  Number(authorshipFirst),
                  Number(authorshipSecond)
                );
                setAuthorshipFirst('');
                setAuthorshipSecond('');
                setIsAuthorshipDialogOpen(false);
              }}
            >
              Claim
            </AxoDialog.Action>
          </AxoDialog.Actions>
        </AxoDialog.Footer>
      </AxoDialog.Content>
    </AxoDialog.Root>
  ) : null;

  const sendButtonFragment = !draftEditMessage ? (
    <>
      <div className="CompositionArea__placeholder" />
      <div className="CompositionArea__button-cell">
        <div className={actionSlotClassName}>
          <AxoIconButton.Root
            symbol="send-fill"
            variant="strong-primary"
            size="md"
            label={i18n('icu:sendMessageToContact')}
            onClick={handleForceSend}
          />
        </div>
      </div>
    </>
  ) : null;

  // Listen for cmd/ctrl-shift-x to toggle large composition mode
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const { shiftKey, ctrlKey, metaKey } = e;
      const key = KeyboardLayout.lookup(e);
      // When using the ctrl key, `key` is `'K'`. When using the cmd key, `key` is `'k'`
      const targetKey = key === 'k' || key === 'K';
      const commandKey = platform === 'darwin' && metaKey;
      const controlKey = platform !== 'darwin' && ctrlKey;
      const commandOrCtrl = commandKey || controlKey;

      // cmd/ctrl-shift-k
      if (targetKey && shiftKey && commandOrCtrl) {
        e.preventDefault();
        setLarge(x => !x);
      }
    };

    document.addEventListener('keydown', handler);

    return () => {
      document.removeEventListener('keydown', handler);
    };
  }, [platform, setLarge]);

  const handleEscape = useCallback(() => {
    if (linkPreviewResult) {
      onCloseLinkPreview(conversationId);
    } else if (quotedMessageId) {
      setQuoteByMessageId(conversationId, undefined);
    } else if (draftEditMessage) {
      discardEditMessage(conversationId);
    }
  }, [
    conversationId,
    discardEditMessage,
    draftEditMessage,
    linkPreviewResult,
    onCloseLinkPreview,
    quotedMessageId,
    setQuoteByMessageId,
  ]);

  useEscapeHandling(handleEscape);

  if (selectedMessageIds != null) {
    return (
      <SelectModeActions
        i18n={i18n}
        selectedMessageIds={selectedMessageIds}
        areSelectedMessagesForwardable={areSelectedMessagesForwardable === true}
        onExitSelectMode={() => {
          toggleSelectMode(false);
        }}
        onDeleteMessages={() => {
          window.reduxActions.globalModals.toggleDeleteMessagesModal({
            conversationId,
            messageIds: selectedMessageIds,
            onDelete() {
              toggleSelectMode(false);
            },
          });
        }}
        onForwardMessages={() => {
          if (selectedMessageIds.length > 0) {
            toggleForwardMessagesModal(
              {
                type: ForwardMessagesModalType.Forward,
                messageIds: selectedMessageIds,
              },
              () => {
                toggleSelectMode(false);
              }
            );
          }
        }}
        showToast={showToast}
      />
    );
  }

  if (isSignalConversation) {
    return null;
  }

  if (terminated) {
    return (
      <div
        className={tw(
          'border-t border-primary py-[16px]',
          'text-center type-body-small text-secondary'
        )}
        data-testid="CompositionArea--group-terminated"
      >
        {i18n('icu:CompositionArea--group-terminated')}
      </div>
    );
  }

  if (
    isBlocked ||
    areWePending ||
    (!acceptedMessageRequest && removalStage !== 'justNotification')
  ) {
    return (
      <MessageRequestActions
        addedByName={addedByName}
        conversationType={conversationType}
        conversationId={conversationId}
        conversationName={conversationName}
        getSharedGroupNames={getSharedGroupNames}
        i18n={i18n}
        isBlocked={isBlocked}
        isHidden={isHidden}
        isReported={isReported}
        acceptConversation={acceptConversation}
        reportSpam={reportSpam}
        blockAndReportSpam={blockAndReportSpam}
        blockConversation={blockConversation}
        deleteConversation={deleteConversation}
      />
    );
  }

  if (conversationType === 'direct' && isSmsOnlyOrUnregistered) {
    return (
      <div
        className={classNames([
          'CompositionArea',
          'CompositionArea--sms-only',
          isFetchingUUID ? 'CompositionArea--pending' : null,
        ])}
      >
        {isFetchingUUID ? (
          <Spinner
            ariaLabel={i18n('icu:CompositionArea--sms-only__spinner-label')}
            role="presentation"
            moduleClassName="module-image-spinner"
            svgSize="small"
          />
        ) : (
          <>
            <h2 className="CompositionArea--sms-only__title">
              {i18n('icu:CompositionArea--sms-only__title')}
            </h2>
            <p className="CompositionArea--sms-only__body">
              {i18n('icu:CompositionArea--sms-only__body')}
            </p>
          </>
        )}
      </div>
    );
  }

  // If no message request, but we haven't shared profile yet, we show profile-sharing UI
  if (
    !left &&
    (conversationType === 'direct' ||
      (conversationType === 'group' && groupVersion === 1)) &&
    isMissingMandatoryProfileSharing
  ) {
    return (
      <MandatoryProfileSharingActions
        addedByName={addedByName}
        conversationId={conversationId}
        conversationType={conversationType}
        conversationName={conversationName}
        i18n={i18n}
        isBlocked={isBlocked}
        isReported={isReported}
        acceptConversation={acceptConversation}
        reportSpam={reportSpam}
        blockAndReportSpam={blockAndReportSpam}
        blockConversation={blockConversation}
        deleteConversation={deleteConversation}
      />
    );
  }

  // If this is a V1 group, now disabled entirely, we show UI to help them upgrade
  if (!left && isGroupV1AndDisabled) {
    return (
      <GroupV1DisabledActions
        conversationId={conversationId}
        i18n={i18n}
        showGV2MigrationDialog={showGV2MigrationDialog}
      />
    );
  }

  if (areWePendingApproval) {
    return (
      <GroupV2PendingApprovalActions
        cancelJoinRequest={cancelJoinRequest}
        conversationId={conversationId}
        i18n={i18n}
      />
    );
  }

  if (announcementsOnly && !areWeAdmin) {
    return (
      <AnnouncementsOnlyGroupBanner
        getPreferredBadge={getPreferredBadge}
        groupAdmins={groupAdmins}
        i18n={i18n}
        memberColors={memberColors}
        showConversation={showConversation}
        theme={theme}
      />
    );
  }

  if (isRecording) {
    return renderSmartCompositionRecording();
  }

  if (
    draftAttachments.length === 1 &&
    draftAttachments[0] != null &&
    isVoiceMessage(draftAttachments[0])
  ) {
    const voiceNoteAttachment = draftAttachments[0];

    if (!voiceNoteAttachment.pending && voiceNoteAttachment.url) {
      return renderSmartCompositionRecordingDraft({ voiceNoteAttachment });
    }
  }

  return (
    <div className="CompositionArea">
      {attachmentToEdit &&
        'url' in attachmentToEdit &&
        attachmentToEdit.url && (
          <MediaEditor
            draftBodyRanges={draftBodyRanges}
            draftText={draftText}
            getPreferredBadge={getPreferredBadge}
            i18n={i18n}
            imageSrc={attachmentToEdit.url}
            imageToBlurHash={imageToBlurHash}
            isCreatingStory={false}
            isFormattingEnabled={isFormattingEnabled}
            isSending={false}
            isHighQuality={shouldSendHighQualityAttachments}
            isViewOnce={isViewOnce}
            showViewOnceToggle={showViewOnceToggle}
            convertDraftBodyRangesIntoHydrated={
              convertDraftBodyRangesIntoHydrated
            }
            onClose={() => setAttachmentToEdit(undefined)}
            onDone={({
              caption,
              captionBodyRanges,
              data,
              contentType,
              blurHash,
              isViewOnce: editorIsViewOnce,
              isHighQuality: editorIsHighQuality,
            }) => {
              const newAttachment = {
                ...attachmentToEdit,
                contentType,
                blurHash,
                data,
                size: data.byteLength,
              };

              addAttachment(conversationId, newAttachment);
              setAttachmentToEdit(undefined);

              if (
                editorIsViewOnce !== undefined &&
                editorIsViewOnce !== isViewOnce
              ) {
                setViewOnce({
                  conversationId,
                  value: editorIsViewOnce,
                  toastNotify: false,
                });
              }

              if (
                editorIsHighQuality !== undefined &&
                editorIsHighQuality !== shouldSendHighQualityAttachments
              ) {
                setMediaQualitySetting(conversationId, editorIsHighQuality);
              }

              onEditorStateChange?.({
                bodyRanges: captionBodyRanges ?? [],
                conversationId,
                messageText: caption ?? '',
                sendCounter,
              });

              inputApiRef.current?.setContents(
                caption ?? '',
                convertDraftBodyRangesIntoHydrated(captionBodyRanges),
                true
              );
            }}
            onSelectEmoji={onSelectEmoji}
            onTextTooLong={onTextTooLong}
            ourConversationId={ourConversationId}
            platform={platform}
            emojiSkinToneDefault={emojiSkinToneDefault}
            sortedGroupMembers={sortedGroupMembers}
          />
        )}
      {isViewOnceActive ? null : (
        <div className="CompositionArea__toggle-large">
          <button
            type="button"
            className={classNames(
              'CompositionArea__toggle-large__button',
              large
                ? 'CompositionArea__toggle-large__button--large-active'
                : null
            )}
            onClick={handleToggleLarge}
            aria-label={i18n('icu:CompositionArea--expand')}
          />
        </div>
      )}
      <div
        className={classNames(
          'CompositionArea__row',
          'CompositionArea__row--column'
        )}
      >
        {isViewOnceActive
          ? null
          : quotedMessageProps && (
              <div className="quote-wrapper">
                <Quote
                  isCompose
                  {...quotedMessageProps}
                  i18n={i18n}
                  onClick={
                    quotedMessageId
                      ? () => scrollToMessage(conversationId, quotedMessageId)
                      : undefined
                  }
                  onClose={() => {
                    setQuoteByMessageId(conversationId, undefined);
                  }}
                />
              </div>
            )}
        {draftAttachments.length ? (
          <div className="CompositionArea__attachment-list">
            <AttachmentList
              attachments={draftAttachments}
              canEditImages
              i18n={i18n}
              onAddAttachment={launchFilePicker}
              onClickAttachment={maybeEditAttachment}
              onClose={() => onClearAttachments(conversationId)}
              onCloseAttachment={attachment => {
                removeAttachment(conversationId, attachment);
              }}
            />
          </div>
        ) : null}
      </div>
      <div
        className={classNames('CompositionArea__row', {
          'CompositionArea__row--padded': !isViewOnceActive && large,
        })}
      >
        {!large ? leftHandSideButtonsFragment : null}
        <div
          className={classNames('CompositionArea__input', {
            'CompositionArea__input--padded': !isViewOnceActive && large,
          })}
        >
          <CompositionInput
            conversationId={conversationId}
            disabled={isDisabled}
            draftBodyRanges={draftBodyRanges}
            draftText={draftText}
            getPreferredBadge={getPreferredBadge}
            i18n={i18n}
            inputApi={inputApiRef}
            isFormattingEnabled={isFormattingEnabled}
            isActive={isActive}
            draftEditMessage={draftEditMessageForInput}
            large={largeForInput}
            linkPreviewLoading={linkPreviewLoadingForInput}
            linkPreviewResult={linkPreviewResultForInput}
            quotedMessageId={quotedMessageIdForInput}
            showRecoveryKeyPasteWarning={textIncludesRecoveryKey}
            onCloseLinkPreview={onCloseLinkPreview}
            onDirtyChange={setDirty}
            onEditorStateChange={onEditorStateChange}
            onSelectEmoji={onSelectEmoji}
            onSubmit={handleSubmit}
            onTextTooLong={onTextTooLong}
            ourConversationId={ourConversationId}
            platform={platform}
            sendCounter={sendCounter}
            shouldHidePopovers={shouldHidePopovers}
            emojiSkinToneDefault={emojiSkinToneDefault ?? null}
            sortedGroupMembers={sortedGroupMembers}
            theme={theme}
            showViewOnceButton={showViewOnceToggle}
            isViewOnceActive={isViewOnceActive}
            onToggleViewOnce={handleToggleViewOnce}
          />
        </div>
        {isViewOnceActive && (
          <div className="CompositionArea__button-cell">
            <div className={actionSlotClassName}>
              <AxoIconButton.Root
                size="md"
                variant="strong-primary"
                symbol="send-fill"
                label={i18n('icu:sendMessageToContact')}
                onClick={handleForceSend}
              />
            </div>
          </div>
        )}
        {!isViewOnceActive && !large && (
          <>
            {!dirty ? micButtonFragment : null}
            {editMessageFragment}
            {personaMenuButton}
            {composerAddMenuButton}
          </>
        )}
      </div>
      {!isViewOnceActive && large ? (
        <div
          className={classNames(
            'CompositionArea__row',
            'CompositionArea__row--control-row'
          )}
        >
          {leftHandSideButtonsFragment}
          {personaMenuButton}
          {composerAddMenuButton}
          {!dirty ? micButtonFragment : null}
          {editMessageFragment}
          {dirty || !shouldShowMicrophone ? sendButtonFragment : null}
        </div>
      ) : null}
      <CompositionUpload
        conversationId={conversationId}
        draftAttachments={draftAttachments}
        i18n={i18n}
        processAttachments={processAttachments}
        ref={fileInputRef}
      />
      <CompositionUpload
        conversationId={conversationId}
        draftAttachments={draftAttachments}
        i18n={i18n}
        processAttachments={processAttachments}
        ref={photoVideoInputRef}
        acceptMediaOnly
        testId="attachfile-input-media"
      />
      {personaTopicDialog}
      {personaAuthorshipDialog}
      {isStatusDialogOpen && (
        <PersonaStatusDialog
          onScanNow={() => scanPersonaCallbacksNow(conversationId)}
          onApproveBadge={(requestEh, slot) =>
            approvePersonaBadge(conversationId, requestEh, slot)
          }
          onDismissBadge={dismissPersonaBadgeRequest}
          onOpenExtraMember={openPersonasExtraMember}
          onRequestReset={() => requestPersonaReset(conversationId)}
          onApproveReset={account =>
            approvePersonaReset(conversationId, account)
          }
          onDismissReset={dismissPersonaReset}
          contactsPanel={personaContactsPanel}
          status={personaStatus}
          i18n={i18n}
          onClose={() => setIsStatusDialogOpen(false)}
        />
      )}
      {isPollModalOpen && (
        <PollCreateModal
          i18n={i18n}
          onClose={handleClosePollModal}
          onSendPoll={handleSendPoll}
        />
      )}
    </div>
  );
});
