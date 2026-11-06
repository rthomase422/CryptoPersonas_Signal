// Copyright 2019 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { PersonaContactsPanel } from '../../components/PersonaContactsPanel.dom.tsx';
import {
  addContactByCode,
  getMyContactCode,
  renewMyContactCode,
} from '../../textsecure/personaRoster.preload.ts';
import { personasGroupStanding } from '../../services/personasPhantom.preload.ts';
import { useCallback, useMemo, useState, memo } from 'react';
import { ipcRenderer } from 'electron';
import { useSelector } from 'react-redux';
import type { StateType } from '../reducer.preload.ts';
import { CompositionArea } from '../../components/CompositionArea.dom.tsx';
import {
  getSelectedBadge,
  setSelectedBadge,
} from '../../services/personasBadgeState.preload.ts';
import type { PersonaBadge } from '../../services/personasBadges.std.ts';
import { useContactNameData } from '../../components/conversation/ContactName.dom.tsx';
import type {
  DraftBodyRanges,
  HydratedBodyRangesType,
} from '../../types/BodyRange.std.ts';
import { hydrateRanges } from '../../util/BodyRange.node.ts';
import { strictAssert } from '../../util/assert.std.ts';
import { getAddedByForGroup } from '../../util/getAddedByForGroup.preload.ts';
import { AutoSubstituteAsciiEmojis } from '../../quill/auto-substitute-ascii-emojis/index.dom.tsx';
import { imageToBlurHash } from '../../util/imageToBlurHash.dom.ts';
import { isConversationSMSOnly } from '../../util/isConversationSMSOnly.std.ts';
import { isSignalConversation } from '../../util/isSignalConversation.dom.ts';
import {
  getErrorDialogAudioRecorderType,
  getRecordingState,
} from '../selectors/audioRecorder.std.ts';
import { getPreferredBadgeSelector } from '../selectors/badges.preload.ts';
import { getComposerStateForConversationIdSelector } from '../selectors/composer.preload.ts';
import {
  getCachedConversationMemberColorsSelector,
  getConversationSelector,
  getGroupAdminsSelector,
  getLastEditableMessageId,
  getMessages,
  getSelectedMessageIds,
  isMissingRequiredProfileSharing,
} from '../selectors/conversations.dom.ts';
import { getHasPanelOpen } from '../selectors/nav.std.ts';
import { getSharedGroupNames } from '../../util/sharedGroupNames.dom.ts';
import {
  getDefaultConversationColor,
  getEmojiSkinToneDefault,
  getItems,
  getTextFormattingEnabled,
} from '../selectors/items.dom.ts';
import { canForward, getPropsForQuote } from '../selectors/message.preload.ts';
import {
  getIntl,
  getPlatform,
  getTheme,
  getUserConversationId,
  getVersion,
} from '../selectors/user.std.ts';
import { SmartCompositionRecording } from './CompositionRecording.preload.tsx';
import type { SmartCompositionRecordingDraftProps } from './CompositionRecordingDraft.preload.tsx';
import { SmartCompositionRecordingDraft } from './CompositionRecordingDraft.preload.tsx';
import { useComposerActions } from '../ducks/composer.preload.ts';
import { useConversationsActions } from '../ducks/conversations.preload.ts';
import { useAudioRecorderActions } from '../ducks/audioRecorder.preload.ts';
import { useEmojisActions } from '../ducks/emojis.preload.ts';
import { useGlobalModalActions } from '../ducks/globalModals.preload.ts';
import { useToastActions } from '../ducks/toast.preload.ts';
import { isShowingAnyModal } from '../selectors/globalModals.std.ts';
import { isConversationEverUnregistered } from '../../util/isConversationUnregistered.dom.ts';
import { isDirectConversation } from '../../util/whatTypeOfConversation.dom.ts';
import { itemStorage } from '../../textsecure/Storage.preload.ts';
import { useNavActions } from '../ducks/nav.std.ts';
import { isFeaturedEnabledSelector } from '../../util/isFeatureEnabled.dom.ts';

function renderSmartCompositionRecording() {
  return <SmartCompositionRecording />;
}

function renderSmartCompositionRecordingDraft(
  draftProps: SmartCompositionRecordingDraftProps
) {
  return <SmartCompositionRecordingDraft {...draftProps} />;
}


// Personas demo: File > Open Extra Member, from the status panel. The main process only
// honors this in the installable build (app/personas.main.ts).
// Stable empties, so a group with no topics or pseudonyms does not re-render the
// composer on every store update.
const NO_TOPICS: ReadonlyArray<{ name: string; context: number }> = [];
const NO_PSEUDONYMS: ReadonlyArray<{ nonce: number; petname?: string; index: number }> =
  [];

function openPersonasExtraMember(slot: 1 | 2): void {
  void ipcRenderer.invoke('personas:open-extra-member', slot);
}

export const SmartCompositionArea = memo(function SmartCompositionArea({
  id,
}: {
  id: string;
}) {
  // Personas demo: the UNVERIFIED badge claim. Held in component state rather than
  // redux because nothing else reads it — the send path reads it straight off disk at
  // send time — and local state is what makes the menu label update on selection.
  const [selectedBadge, setSelectedBadgeState] = useState<
    PersonaBadge | undefined
  >(() => getSelectedBadge());
  const setPersonaBadge = useCallback((badge: PersonaBadge | undefined) => {
    setSelectedBadge(badge);
    setSelectedBadgeState(badge);
  }, []);

  const conversationSelector = useSelector(getConversationSelector);
  const conversation = conversationSelector(id);
  const isGroup = conversation.type === 'group';
  strictAssert(conversation, `Conversation id ${id} not found!`);

  const i18n = useSelector(getIntl);
  const theme = useSelector(getTheme);
  const emojiSkinToneDefault = useSelector(getEmojiSkinToneDefault);
  const selectedMessageIds = useSelector(getSelectedMessageIds);
  const messageLookup = useSelector(getMessages);
  const isFormattingEnabled = useSelector(getTextFormattingEnabled);
  const items = useSelector(getItems);
  const version = useSelector(getVersion);
  const lastEditableMessageId = useSelector(getLastEditableMessageId);
  const platform = useSelector(getPlatform);
  const shouldHidePopovers = useSelector(getHasPanelOpen);
  const recordingState = useSelector(getRecordingState);
  const errorDialogAudioRecorderType = useSelector(
    getErrorDialogAudioRecorderType
  );
  const hasGlobalModalOpen = useSelector(isShowingAnyModal);
  const hasPanelOpen = useSelector(getHasPanelOpen);
  const getGroupAdmins = useSelector(getGroupAdminsSelector);
  const getPreferredBadge = useSelector(getPreferredBadgeSelector);
  const composerStateForConversationIdSelector = useSelector(
    getComposerStateForConversationIdSelector
  );
  const composerState = composerStateForConversationIdSelector(id);
  const {
    announcementsOnly,
    areWeAdmin,
    draftEditMessage,
    draftBodyRanges,
    terminated,
  } = conversation;
  const {
    attachments: draftAttachments,
    focusCounter,
    disabledCounter,
    isViewOnce,
    linkPreviewLoading,
    linkPreviewResult,
    sendCounter,
    shouldSendHighQualityAttachments,
  } = composerState;

  const isDisabled = disabledCounter > 0;

  const areSelectedMessagesForwardable = useMemo(() => {
    return selectedMessageIds?.every(messageId => {
      const message = messageLookup[messageId];
      if (!message) {
        return false;
      }
      return canForward(message);
    });
  }, [messageLookup, selectedMessageIds]);

  const isActive = useMemo(() => {
    return !hasGlobalModalOpen && !hasPanelOpen;
  }, [hasGlobalModalOpen, hasPanelOpen]);

  const groupAdmins = useMemo(() => {
    return getGroupAdmins(id);
  }, [getGroupAdmins, id]);
  const getMemberColors = useSelector(
    getCachedConversationMemberColorsSelector
  );
  const memberColors = getMemberColors(id);

  const addedBy = useMemo(() => {
    if (conversation.type === 'group') {
      return getAddedByForGroup(conversation);
    }
    return null;
  }, [conversation]);

  const conversationName = useContactNameData(conversation);
  strictAssert(conversationName, 'conversationName is required');
  const addedByName = useContactNameData(addedBy);

  const hydratedDraftBodyRanges = useMemo(() => {
    return hydrateRanges(draftBodyRanges, conversationSelector);
  }, [conversationSelector, draftBodyRanges]);

  const convertDraftBodyRangesIntoHydrated = useCallback(
    (
      bodyRanges: DraftBodyRanges | undefined
    ): HydratedBodyRangesType | undefined => {
      return hydrateRanges(bodyRanges, conversationSelector);
    },
    [conversationSelector]
  );

  let { quotedMessage } = composerState;
  if (!quotedMessage && draftEditMessage?.quote) {
    quotedMessage = {
      conversationId: id,
      quote: draftEditMessage.quote,
    };
  }

  const ourConversationId = useSelector(getUserConversationId);
  const defaultConversationColor = useSelector(getDefaultConversationColor);

  const quotedMessageProps = useMemo(() => {
    return quotedMessage
      ? getPropsForQuote(quotedMessage, {
          conversationSelector,
          ourConversationId,
          defaultConversationColor,
          isGroup,
        })
      : undefined;
  }, [
    quotedMessage,
    conversationSelector,
    ourConversationId,
    defaultConversationColor,
    isGroup,
  ]);

  const {
    onTextTooLong,
    onCloseLinkPreview,
    addAttachment,
    removeAttachment,
    onClearAttachments,
    processAttachments,
    setMediaQualitySetting,
    setQuoteByMessageId,
    setViewOnce,
    cancelJoinRequest,
    sendStickerMessage,
    sendEditedMessage,
    sendMultiMediaMessage,
    sendPoll,
    createPersonaTopic,
    refreshPersonaStatus,
    requestPersonaBadge,
    dismissPersonaBadgeRequest,
    requestPersonaReset,
    turnOnPersonas,
    approvePersonaReset,
    dismissPersonaReset,
    provePersonaBadge,
    joinPersonaBulletin,
    approvePersonaBadge,
    createPersonaPseudonym,
    scanPersonaCallbacksNow,
    sendPersonaAuthorshipClaim,
    setComposerFocus,
  } = useComposerActions();
  // Personas demo: topics (and their contexts) known to this instance. Held
  // in redux because this component's renderer half cannot import preload modules.
  // Per personas group: this conversation's own topics and pseudonyms.
  const personaTopics = useSelector(
    (state: StateType) =>
      (conversation.groupId
        ? state.composer.personaTopics[conversation.groupId]
        : undefined) ?? NO_TOPICS
  );
  const personaStatus = useSelector(
    (state: StateType) => state.composer.personaStatus
  );
  const personaPseudonyms = useSelector(
    (state: StateType) =>
      (conversation.groupId
        ? state.composer.personaPseudonyms[conversation.groupId]
        : undefined) ?? NO_PSEUDONYMS
  );
  const {
    discardEditMessage,
    acceptConversation,
    blockAndReportSpam,
    blockConversation,
    reportSpam,
    deleteConversation,
    toggleSelectMode,
    scrollToMessage,
    setMessageToEdit,
    showConversation,
  } = useConversationsActions();
  const { pushPanelForConversation } = useNavActions();
  const {
    cancelRecording,
    completeRecording,
    warmupRecording,
    startRecording,
    errorRecording,
  } = useAudioRecorderActions();
  const { onUseEmoji } = useEmojisActions();
  const {
    showGV2MigrationDialog,
    toggleForwardMessagesModal,
    toggleDraftGifMessageSendModal,
  } = useGlobalModalActions();
  const { showToast } = useToastActions();
  const { onEditorStateChange } = useComposerActions();

  AutoSubstituteAsciiEmojis.enable(itemStorage.get('autoConvertEmoji', true));
  const { accountEntropyPool } = items;

  const textIncludesRecoveryKey = useCallback(
    (text: string) => {
      if (!accountEntropyPool) {
        return false;
      }
      const normalizedText = text
        .toUpperCase()
        .replace(/\s/g, '')
        .replace(/#/g, 'O')
        .replace(/=/g, '0');

      return normalizedText.includes(accountEntropyPool.toUpperCase());
    },
    [accountEntropyPool]
  );

  return (
    <CompositionArea
      // Base
      conversationId={id}
      draftBodyRanges={hydratedDraftBodyRanges ?? null}
      draftEditMessage={draftEditMessage ?? null}
      draftText={conversation.draftText ?? null}
      focusCounter={focusCounter}
      getPreferredBadge={getPreferredBadge}
      i18n={i18n}
      isDisabled={isDisabled}
      isFormattingEnabled={isFormattingEnabled}
      isPollSend1to1Enabled={isFeaturedEnabledSelector({
        betaKey: 'desktop.pollSend1to1.beta',
        prodKey: 'desktop.pollSend1to1.prod',
        currentVersion: version,
        remoteConfig: items.remoteConfig,
      })}
      isActive={isActive}
      lastEditableMessageId={lastEditableMessageId ?? null}
      platform={platform}
      ourConversationId={ourConversationId}
      sendCounter={sendCounter}
      shouldHidePopovers={shouldHidePopovers}
      theme={theme}
      convertDraftBodyRangesIntoHydrated={convertDraftBodyRangesIntoHydrated}
      onTextTooLong={onTextTooLong}
      textIncludesRecoveryKey={textIncludesRecoveryKey}
      pushPanelForConversation={pushPanelForConversation}
      discardEditMessage={discardEditMessage}
      onCloseLinkPreview={onCloseLinkPreview}
      onEditorStateChange={onEditorStateChange}
      // MediaEditor
      conversationSelector={conversationSelector}
      // AudioCapture
      errorDialogAudioRecorderType={errorDialogAudioRecorderType ?? null}
      recordingState={recordingState}
      cancelRecording={cancelRecording}
      completeRecording={completeRecording}
      warmupRecording={warmupRecording}
      startRecording={startRecording}
      errorRecording={errorRecording}
      // AttachmentsList
      draftAttachments={draftAttachments}
      addAttachment={addAttachment}
      removeAttachment={removeAttachment}
      onClearAttachments={onClearAttachments}
      processAttachments={processAttachments}
      // MediaEditor
      imageToBlurHash={imageToBlurHash}
      // MediaQualitySelector
      shouldSendHighQualityAttachments={
        shouldSendHighQualityAttachments !== undefined
          ? shouldSendHighQualityAttachments
          : itemStorage.get('sent-media-quality') === 'high'
      }
      setMediaQualitySetting={setMediaQualitySetting}
      // StagedLinkPreview
      linkPreviewLoading={linkPreviewLoading}
      linkPreviewResult={linkPreviewResult ?? null}
      // Quote
      quotedMessageId={quotedMessage?.quote?.messageId ?? null}
      quotedMessageProps={quotedMessageProps ?? null}
      quotedMessageAuthorAci={quotedMessage?.quote?.authorAci ?? null}
      quotedMessageSentAt={quotedMessage?.quote?.id ?? null}
      setQuoteByMessageId={setQuoteByMessageId}
      // View Once
      isViewOnce={isViewOnce}
      setViewOnce={setViewOnce}
      // Fun Picker
      emojiSkinToneDefault={emojiSkinToneDefault}
      onSelectEmoji={onUseEmoji}
      // Message Requests
      acceptedMessageRequest={conversation.acceptedMessageRequest ?? null}
      removalStage={conversation.removalStage ?? null}
      addedByName={addedByName}
      conversationName={conversationName}
      conversationType={conversation.type}
      isBlocked={conversation.isBlocked ?? false}
      isReported={conversation.isReported ?? false}
      isHidden={conversation.removalStage != null}
      isSmsOnlyOrUnregistered={
        isDirectConversation(conversation) &&
        (isConversationSMSOnly(conversation) ||
          isConversationEverUnregistered(conversation))
      }
      isFetchingUUID={conversation.isFetchingUUID ?? null}
      isMissingMandatoryProfileSharing={isMissingRequiredProfileSharing(
        conversation
      )}
      acceptConversation={acceptConversation}
      blockAndReportSpam={blockAndReportSpam}
      blockConversation={blockConversation}
      reportSpam={reportSpam}
      deleteConversation={deleteConversation}
      getSharedGroupNames={getSharedGroupNames}
      // Signal Conversation
      isSignalConversation={isSignalConversation(conversation)}
      // Groups
      groupVersion={conversation.groupVersion ?? null}
      isGroupV1AndDisabled={conversation.isGroupV1AndDisabled ?? null}
      left={conversation.left ?? null}
      announcementsOnly={announcementsOnly ?? null}
      areWeAdmin={areWeAdmin ?? null}
      areWePending={conversation.areWePending ?? null}
      areWePendingApproval={conversation.areWePendingApproval ?? null}
      groupAdmins={groupAdmins}
      memberColors={memberColors}
      renderSmartCompositionRecording={renderSmartCompositionRecording}
      renderSmartCompositionRecordingDraft={
        renderSmartCompositionRecordingDraft
      }
      showGV2MigrationDialog={showGV2MigrationDialog}
      cancelJoinRequest={cancelJoinRequest}
      sortedGroupMembers={conversation.sortedGroupMembers ?? null}
      terminated={terminated ?? null}
      // Select Mode
      selectedMessageIds={selectedMessageIds}
      areSelectedMessagesForwardable={areSelectedMessagesForwardable}
      toggleSelectMode={toggleSelectMode}
      toggleForwardMessagesModal={toggleForwardMessagesModal}
      // DraftGifMessageSendModal
      toggleDraftGifMessageSendModal={toggleDraftGifMessageSendModal}
      // Dispatch
      showToast={showToast}
      sendStickerMessage={sendStickerMessage}
      sendEditedMessage={sendEditedMessage}
      sendMultiMediaMessage={sendMultiMediaMessage}
      sendPoll={sendPoll}
      personaTopics={personaTopics}
      createPersonaTopic={createPersonaTopic}
      personaStatus={personaStatus}
      heldBadges={personaStatus?.heldBadges ?? []}
      // A badge request is a RECORD, so it needs this member to be on the bulletin.
      // Defaults to false while the status is still unknown: offering a control that
      // throws "this member is not on the bulletin yet" is worse than one that says
      // why it is not ready.
      personaJoined={personaStatus?.joined ?? false}
      requestPersonaBadge={requestPersonaBadge}
      dismissPersonaBadgeRequest={(requestEh: string) =>
        dismissPersonaBadgeRequest(id, requestEh)
      }
      requestPersonaReset={requestPersonaReset}
      // Personas are per group, and on in ONE group per app for now: this says whether
      // this is that group. Read on every render (the bundle can arrive at any time).
      personaGroupStanding={personasGroupStanding(
        window.ConversationController.get(id)
      )}
      turnOnPersonas={turnOnPersonas}
      approvePersonaReset={approvePersonaReset}
      dismissPersonaReset={(account: string) => dismissPersonaReset(id, account)}
      provePersonaBadge={provePersonaBadge}
      joinPersonaBulletin={joinPersonaBulletin}
      approvePersonaBadge={approvePersonaBadge}
      refreshPersonaStatus={refreshPersonaStatus}
      personaPseudonyms={personaPseudonyms}
      createPersonaPseudonym={() => createPersonaPseudonym(id)}
      scanPersonaCallbacksNow={scanPersonaCallbacksNow}
      openPersonasExtraMember={openPersonasExtraMember}
      personaContactsPanel={
        <PersonaContactsPanel
          loadCode={getMyContactCode}
          renewCode={renewMyContactCode}
          addByCode={addContactByCode}
        />
      }
      sendPersonaAuthorshipClaim={sendPersonaAuthorshipClaim}
      selectedBadge={selectedBadge}
      setPersonaBadge={setPersonaBadge}
      scrollToMessage={scrollToMessage}
      setComposerFocus={setComposerFocus}
      setMessageToEdit={setMessageToEdit}
      showConversation={showConversation}
    />
  );
});
