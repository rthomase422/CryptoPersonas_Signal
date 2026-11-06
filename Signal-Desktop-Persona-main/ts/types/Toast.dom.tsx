// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

export enum ToastType {
  AddingUserToGroup = 'AddingUserToGroup',
  AddedUsersToCall = 'AddedUsersToCall',
  AlreadyGroupMember = 'AlreadyGroupMember',
  AlreadyRequestedToJoin = 'AlreadyRequestedToJoin',
  AttachmentDownloadFailed = 'AttachmentDownloadFailed',
  AttachmentDownloadStillInProgress = 'AttachmentDownloadStillInProgress',
  Blocked = 'Blocked',
  BlockedGroup = 'BlockedGroup',
  CallHistoryCleared = 'CallHistoryCleared',
  CallQualitySurveyFailed = 'CallQualitySurveyFailed',
  CallQualitySurveySuccess = 'CallQualitySurveySuccess',
  CaptchaFailed = 'CaptchaFailed',
  CaptchaSolved = 'CaptchaSolved',
  CannotAddMemberLabel = 'CannotAddMemberLabel',
  CannotEditMessage = 'CannotEditMessage',
  CannotForwardEmptyMessage = 'CannotForwardEmptyMessage',
  CannotMixMultiAndNonMultiAttachments = 'CannotMixMultiAndNonMultiAttachments',
  CannotOpenGiftBadgeIncoming = 'CannotOpenGiftBadgeIncoming',
  CannotOpenGiftBadgeOutgoing = 'CannotOpenGiftBadgeOutgoing',
  CannotStartGroupCall = 'CannotStartGroupCall',
  ChatFolderCreated = 'ChatFolderCreated',
  ChatFolderAddedChat = 'ChatFolderAddedChat',
  ChatFolderRemovedChat = 'ChatFolderRemovedChat',
  ConversationArchived = 'ConversationArchived',
  ConversationMarkedUnread = 'ConversationMarkedUnread',
  ConversationRemoved = 'ConversationRemoved',
  ConversationUnarchived = 'ConversationUnarchived',
  CopiedBackupKey = 'CopiedBackupKey',
  CopiedCallLink = 'CopiedCallLink',
  CopiedStickerPackLink = 'CopiedStickerPackLink',
  CopiedUsername = 'CopiedUsername',
  CopiedUsernameLink = 'CopiedUsernameLink',
  DangerousFileType = 'DangerousFileType',
  DecryptionError = 'DecryptionError',
  DebugLogError = 'DebugLogError',
  DeleteForEveryoneFailed = 'DeleteForEveryoneFailed',
  DonationCanceled = 'DonationCanceled',
  DonationCanceledWithView = 'DonationCanceledWithView',
  DonationCompleted = 'DonationCompleted',
  DonationConfirmationNeeded = 'DonationConfirmationNeeded',
  DonationError = 'DonationError',
  DonationPaypalCanceled = 'DonationPaypalCanceled',
  DonationPaypalConfirmationNeeded = 'DonationPaypalConfirmationNeeded',
  DonationPaypalError = 'DonationPaypalError',
  DonationProcessing = 'DonationProcessing',
  DonationVerificationNeeded = 'DonationVerificationNeeded',
  DonationVerificationFailed = 'DonationVerificationFailed',
  Error = 'Error',
  Expired = 'Expired',
  FailedToDeleteUsername = 'FailedToDeleteUsername',
  FailedToFetchPhoneNumber = 'FailedToFetchPhoneNumber',
  FailedToFetchUsername = 'FailedToFetchUsername',
  FailedToImportBackup = 'FailedToImportBackup',
  FileSaved = 'FileSaved',
  FileSize = 'FileSize',
  GroupLinkCopied = 'GroupLinkCopied',
  InvalidConversation = 'InvalidConversation',
  InvalidStorageServiceHeaders = 'InvalidStorageServiceHeaders',
  LeftGroup = 'LeftGroup',
  LinkCopied = 'LinkCopied',
  LoadingFullLogs = 'LoadingFullLogs',
  _InternalMainProcessLoggingError = '_InternalMainProcessLoggingError',
  _InternalHeapSizeWarning = '_InternalHeapSizeWarning',
  MaxAttachments = 'MaxAttachments',
  MediaNoLongerAvailable = 'MediaNoLongerAvailable',
  MessageBodyTooLong = 'MessageBodyTooLong',
  MessageLoop = 'MessageLoop',
  NotificationProfileUpdate = 'NotificationProfileUpdate',
  OriginalMessageNotFound = 'OriginalMessageNotFound',
  PinnedConversationsFull = 'PinnedConversationsFull',
  PinnedMessageNotFound = 'PinnedMessageNotFound',
  PollNotFound = 'PollNotFound',
  // Personas demo: a thumbs reaction on a persona post becomes a ZK RATE record rather
  // than a visible Signal reaction, so without a toast the gesture produces no feedback
  // at all and reads as broken. See personasActions maybeSendPersonaRateForReaction.
  PersonaRated = 'PersonaRated',
  // Personas demo: a non-thumbs reaction on a persona post was blocked because an
  // ordinary Signal reaction would be sent from the reactor's real account.
  PersonaReactionBlocked = 'PersonaReactionBlocked',
  // Personas demo: declined to rate the user's own persona post, because self-rating is
  // undetectable to the protocol and would inflate their own reputation.
  PersonaSelfRateBlocked = 'PersonaSelfRateBlocked',
  // Personas demo: this member's own scan just absorbed a ban. Raised at the moment the
  // flag flips, because that is the only moment the client can be sure the member knows
  // — the ban record itself is anonymous and they may never see it.
  PersonaBanned = 'PersonaBanned',
  PersonaViewsDiverged = 'PersonaViewsDiverged',
  PersonaRecordLost = 'PersonaRecordLost',
  PersonaBadgeRequested = 'PersonaBadgeRequested',
  PersonaBadgeApproved = 'PersonaBadgeApproved',
  // Personas demo: a badge request hidden from THIS admin's queue. Worded as "hidden",
  // never "denied" — no deny record exists, so nothing was broadcast.
  PersonaBadgeDismissed = 'PersonaBadgeDismissed',
  // Personas demo: a persona action was refused, and the REASON is carried through to
  // the screen. The generic Error toast ("Something went wrong") used to be the only
  // thing a refusal produced, which meant the one fact needed to fix it — scan
  // unfinished, not joined, badge already held, engine unavailable — existed solely in
  // app.log. A demo where diagnosing a button press requires reading a log file is a
  // demo that fails in front of an audience.
  PersonaActionFailed = 'PersonaActionFailed',
  // Personas demo: a badge POSSESSION PROOF was published. Distinct from
  // PersonaBadgeApproved (an admin granted it) and from selecting the decorative label.
  PersonaBadgeProved = 'PersonaBadgeProved',
  // Personas demo: a scan absorbed something. Named so the two outcomes of pressing
  // "Scan now" are distinguishable — absorbing nothing is normal, and looked identical
  // to absorbing a badge, which made an approved-but-unscanned badge inexplicable.
  PersonaScanAbsorbed = 'PersonaScanAbsorbed',
  PersonaScanEmpty = 'PersonaScanEmpty',
  ReactionFailed = 'ReactionFailed',
  ReceiptSaved = 'ReceiptSaved',
  ReceiptSaveFailed = 'ReceiptSaveFailed',
  ReportedSpam = 'ReportedSpam',
  RemoteConfigChanged = 'RemoteConfigChanged',
  ReportedSpamAndBlocked = 'ReportedSpamAndBlocked',
  SQLError = 'SQLError',
  StickerPackInstallFailed = 'StickerPackInstallFailed',
  StoryMuted = 'StoryMuted',
  StoryReact = 'StoryReact',
  StoryReply = 'StoryReply',
  StoryVideoError = 'StoryVideoError',
  StoryVideoUnsupported = 'StoryVideoUnsupported',
  TapToViewExpiredIncoming = 'TapToViewExpiredIncoming',
  TapToViewExpiredOutgoing = 'TapToViewExpiredOutgoing',
  TooManyMessagesToDeleteForEveryone = 'TooManyMessagesToDeleteForEveryone',
  TooManyMessagesToForward = 'TooManyMessagesToForward',
  TransportError = 'TransportError',
  UnableToLoadAttachment = 'UnableToLoadAttachment',
  UnableToDownloadFromBackupTier = 'UnableToDownloadFromBackupTier',
  UnsupportedMultiAttachment = 'UnsupportedMultiAttachment',
  UnsupportedOS = 'UnsupportedOS',
  UserAddedToGroup = 'UserAddedToGroup',
  UsernameRecovered = 'UsernameRecovered',
  ViewOnceDisabled = 'ViewOnceDisabled',
  ViewOnceEnabled = 'ViewOnceEnabled',
  VideoFileSize = 'VideoFileSize',
  VoiceNoteLimit = 'VoiceNoteLimit',
  VoiceNoteMustBeTheOnlyAttachment = 'VoiceNoteMustBeTheOnlyAttachment',
  WhoCanFindMeReadOnly = 'WhoCanFindMeReadOnly',
}

export type AnyToast =
  | { toastType: ToastType.AddingUserToGroup; parameters: { contact: string } }
  | {
      toastType: ToastType.AddedUsersToCall;
      parameters: { count: number };
    }
  | { toastType: ToastType.AlreadyGroupMember }
  | { toastType: ToastType.AlreadyRequestedToJoin }
  | {
      toastType: ToastType.AttachmentDownloadFailed;
      parameters: { messageId: string };
    }
  | {
      toastType: ToastType.AttachmentDownloadStillInProgress;
      parameters: { count: number };
    }
  | { toastType: ToastType.Blocked }
  | { toastType: ToastType.BlockedGroup }
  | { toastType: ToastType.CallHistoryCleared }
  | {
      toastType: ToastType.CallQualitySurveyFailed;
      parameters: { canRetry: boolean };
    }
  | { toastType: ToastType.CallQualitySurveySuccess }
  | { toastType: ToastType.CannotAddMemberLabel }
  | { toastType: ToastType.CannotEditMessage }
  | { toastType: ToastType.CannotForwardEmptyMessage }
  | { toastType: ToastType.CannotMixMultiAndNonMultiAttachments }
  | { toastType: ToastType.CannotOpenGiftBadgeIncoming }
  | { toastType: ToastType.CannotOpenGiftBadgeOutgoing }
  | { toastType: ToastType.CannotStartGroupCall }
  | { toastType: ToastType.CaptchaFailed }
  | { toastType: ToastType.CaptchaSolved }
  | {
      toastType: ToastType.ChatFolderAddedChat;
      parameters: { chatFolderName: string };
    }
  | {
      toastType: ToastType.ChatFolderRemovedChat;
      parameters: { chatFolderName: string };
    }
  | {
      toastType: ToastType.ChatFolderCreated;
      parameters: { chatFolderName: string };
    }
  | {
      toastType: ToastType.ConversationArchived;
      parameters: { conversationId: string; wasPinned: boolean };
    }
  | { toastType: ToastType.ConversationMarkedUnread }
  | { toastType: ToastType.ConversationRemoved; parameters: { title: string } }
  | { toastType: ToastType.ConversationUnarchived }
  | { toastType: ToastType.CopiedBackupKey }
  | { toastType: ToastType.CopiedCallLink }
  | { toastType: ToastType.CopiedStickerPackLink }
  | { toastType: ToastType.CopiedUsername }
  | { toastType: ToastType.CopiedUsernameLink }
  | { toastType: ToastType.DangerousFileType }
  | { toastType: ToastType.DebugLogError }
  | { toastType: ToastType.DeleteForEveryoneFailed }
  | { toastType: ToastType.DonationCanceled }
  | { toastType: ToastType.DonationCanceledWithView }
  | { toastType: ToastType.DonationCompleted }
  | { toastType: ToastType.DonationConfirmationNeeded }
  | { toastType: ToastType.DonationError }
  | { toastType: ToastType.DonationPaypalCanceled }
  | { toastType: ToastType.DonationPaypalConfirmationNeeded }
  | { toastType: ToastType.DonationPaypalError }
  | { toastType: ToastType.DonationProcessing }
  | { toastType: ToastType.DonationVerificationFailed }
  | { toastType: ToastType.DonationVerificationNeeded }
  | { toastType: ToastType.Error }
  | { toastType: ToastType.Expired }
  | { toastType: ToastType.FailedToDeleteUsername }
  | { toastType: ToastType.FailedToFetchPhoneNumber }
  | { toastType: ToastType.FailedToFetchUsername }
  | { toastType: ToastType.FailedToImportBackup }
  | {
      toastType: ToastType.FileSaved;
      parameters: { fullPath: string; countOfFiles?: number };
    }
  | {
      toastType: ToastType.FileSize | ToastType.VideoFileSize;
      parameters: { limit: number; units: string };
    }
  | { toastType: ToastType.GroupLinkCopied }
  | {
      toastType: ToastType.DecryptionError;
      parameters: {
        name: string;
        deviceId: number;
      };
    }
  | { toastType: ToastType.InvalidConversation }
  | { toastType: ToastType.InvalidStorageServiceHeaders }
  | { toastType: ToastType.LeftGroup }
  | { toastType: ToastType.LinkCopied }
  | { toastType: ToastType.LoadingFullLogs }
  | {
      toastType: ToastType._InternalMainProcessLoggingError;
      parameters: { count: number; logLines: Array<string> };
    }
  | { toastType: ToastType._InternalHeapSizeWarning }
  | { toastType: ToastType.MaxAttachments }
  | { toastType: ToastType.MediaNoLongerAvailable }
  | { toastType: ToastType.MessageBodyTooLong }
  | { toastType: ToastType.MessageLoop }
  | {
      toastType: ToastType.NotificationProfileUpdate;
      parameters: { enabled: boolean; name: string };
    }
  | { toastType: ToastType.OriginalMessageNotFound }
  | {
      toastType: ToastType.PinnedConversationsFull;
      maxPinnedConversations: number;
    }
  | { toastType: ToastType.PinnedMessageNotFound }
  | { toastType: ToastType.PollNotFound }
  | { toastType: ToastType.PersonaRated; parameters: { delta: number } }
  | { toastType: ToastType.PersonaReactionBlocked }
  | { toastType: ToastType.PersonaSelfRateBlocked }
  | { toastType: ToastType.PersonaBanned }
  | { toastType: ToastType.PersonaViewsDiverged }
  | { toastType: ToastType.PersonaRecordLost }
  | { toastType: ToastType.PersonaBadgeRequested }
  | { toastType: ToastType.PersonaBadgeApproved }
  | { toastType: ToastType.PersonaBadgeDismissed }
  | { toastType: ToastType.PersonaActionFailed; parameters: { reason: string } }
  | { toastType: ToastType.PersonaBadgeProved; parameters: { badge: string } }
  | {
      toastType: ToastType.PersonaScanAbsorbed;
      parameters: { gained: string };
    }
  | { toastType: ToastType.PersonaScanEmpty }
  | { toastType: ToastType.ReactionFailed }
  | {
      toastType: ToastType.RemoteConfigChanged;
      changes: ReadonlyArray<{
        name: string;
        from: string;
        to: string;
      }>;
    }
  | {
      toastType: ToastType.ReceiptSaved;
      parameters: { fullPath: string };
    }
  | { toastType: ToastType.ReceiptSaveFailed }
  | { toastType: ToastType.ReportedSpam }
  | { toastType: ToastType.ReportedSpamAndBlocked }
  | { toastType: ToastType.StickerPackInstallFailed }
  | { toastType: ToastType.SQLError }
  | { toastType: ToastType.StoryMuted }
  | { toastType: ToastType.StoryReact }
  | { toastType: ToastType.StoryReply }
  | { toastType: ToastType.StoryVideoError }
  | { toastType: ToastType.StoryVideoUnsupported }
  | { toastType: ToastType.TapToViewExpiredIncoming }
  | { toastType: ToastType.TapToViewExpiredOutgoing }
  | {
      toastType: ToastType.TooManyMessagesToDeleteForEveryone;
      parameters: { count: number };
    }
  | { toastType: ToastType.TooManyMessagesToForward }
  | { toastType: ToastType.TransportError }
  | { toastType: ToastType.UnableToDownloadFromBackupTier }
  | { toastType: ToastType.UnableToLoadAttachment }
  | { toastType: ToastType.UnsupportedMultiAttachment }
  | { toastType: ToastType.UnsupportedOS }
  | {
      toastType: ToastType.UserAddedToGroup;
      parameters: { contact: string; group: string };
    }
  | {
      toastType: ToastType.UsernameRecovered;
      parameters: { username: string };
    }
  | { toastType: ToastType.ViewOnceDisabled }
  | { toastType: ToastType.ViewOnceEnabled }
  | { toastType: ToastType.VoiceNoteLimit }
  | { toastType: ToastType.VoiceNoteMustBeTheOnlyAttachment }
  | { toastType: ToastType.WhoCanFindMeReadOnly };
