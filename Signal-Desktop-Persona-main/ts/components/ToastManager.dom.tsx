// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import type { JSX } from 'react';

import classNames from 'classnames';
import { createPortal } from 'react-dom';

import { SECOND } from '../util/durations/index.std.ts';
import { Toast } from './Toast.dom.tsx';
import { WidthBreakpoint } from './_util.std.ts';
import { UsernameMegaphone } from './UsernameMegaphone.dom.tsx';
import { assertDev } from '../util/assert.std.ts';
import { missingCaseError } from '../util/missingCaseError.std.ts';
import { ToastType } from '../types/Toast.dom.tsx';
import { MegaphoneType } from '../types/Megaphone.std.ts';
import { NavTab, SettingsPage } from '../types/Nav.std.ts';
import { AxoSymbol } from '../axo/AxoSymbol.dom.tsx';
import { tw } from '../axo/tw.dom.tsx';

import type { LocalizerType } from '../types/Util.std.ts';
import type { AnyToast } from '../types/Toast.dom.tsx';
import type { AnyActionableMegaphone } from '../types/Megaphone.std.ts';
import type { Location } from '../types/Nav.std.ts';
import { I18n } from './I18n.dom.tsx';
import { UserText } from './UserText.dom.tsx';
import { RemoteMegaphone } from './RemoteMegaphone.dom.tsx';

export type PropsType = {
  changeLocation: (newLocation: Location) => unknown;
  expandNarrowLeftPane: () => void;
  hideToast: () => unknown;
  i18n: LocalizerType;
  openFileInFolder: (target: string) => unknown;
  saveHeapSnapshot: () => unknown;
  OS: string;
  onShowDebugLog: () => unknown;
  onUndoArchive: (
    conversationId: string,
    options?: { wasPinned?: boolean }
  ) => unknown;
  retryCallQualitySurvey: () => unknown;
  setDidResumeDonation: (didResume: boolean) => unknown;
  toast?: AnyToast;
  megaphone?: AnyActionableMegaphone;
  centerToast?: boolean;
  containerWidthBreakpoint: WidthBreakpoint | null;
  isCompositionAreaVisible?: boolean;
  isInFullScreenCall: boolean;
};

const SHORT_TIMEOUT = 3 * SECOND;

function renderToast({
  changeLocation,
  hideToast,
  i18n,
  openFileInFolder,
  saveHeapSnapshot,
  onShowDebugLog,
  onUndoArchive,
  retryCallQualitySurvey,
  setDidResumeDonation,
  OS,
  toast,
}: PropsType): JSX.Element | null {
  if (toast === undefined) {
    return null;
  }

  const { toastType } = toast;

  if (toastType === ToastType.AddingUserToGroup) {
    return (
      <Toast onClose={hideToast} timeout={SHORT_TIMEOUT}>
        {i18n('icu:AddUserToAnotherGroupModal__toast--adding-user-to-group', {
          contact: toast.parameters.contact,
        })}
      </Toast>
    );
  }

  if (toastType === ToastType.AddedUsersToCall) {
    return (
      <Toast onClose={hideToast} timeout={SHORT_TIMEOUT}>
        {i18n('icu:CallingPendingParticipants__Toast--added-users-to-call', {
          count: toast.parameters.count,
        })}
      </Toast>
    );
  }

  if (toastType === ToastType.AlreadyGroupMember) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:GroupV2--join--already-in-group')}
      </Toast>
    );
  }

  if (toastType === ToastType.AlreadyRequestedToJoin) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:GroupV2--join--already-awaiting-approval')}
      </Toast>
    );
  }

  if (toastType === ToastType.AttachmentDownloadFailed) {
    return (
      <Toast onClose={hideToast}>{i18n('icu:Toast--download-failed')}</Toast>
    );
  }

  if (toastType === ToastType.AttachmentDownloadStillInProgress) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:attachmentStillDownloading', {
          count: toast.parameters.count,
        })}
      </Toast>
    );
  }

  if (toastType === ToastType.Blocked) {
    return <Toast onClose={hideToast}>{i18n('icu:unblockToSend')}</Toast>;
  }

  if (toastType === ToastType.BlockedGroup) {
    return <Toast onClose={hideToast}>{i18n('icu:unblockGroupToSend')}</Toast>;
  }

  if (toastType === ToastType.CallHistoryCleared) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:CallsTab__ToastCallHistoryCleared')}
      </Toast>
    );
  }

  if (toastType === ToastType.CallQualitySurveyFailed) {
    const { canRetry } = toast.parameters;

    return (
      <Toast
        onClose={hideToast}
        toastAction={
          canRetry
            ? {
                label: i18n('icu:CallQualitySurvey__SubmissionFailed__Retry'),
                onClick: () => {
                  retryCallQualitySurvey();
                },
              }
            : undefined
        }
      >
        {i18n('icu:CallQualitySurvey__SubmissionFailed')}
      </Toast>
    );
  }

  if (toastType === ToastType.CallQualitySurveySuccess) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:CallQualitySurvey__SubmissionSuccess')}
      </Toast>
    );
  }

  if (toastType === ToastType.CannotAddMemberLabel) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:ToastManager__CannotAddMemberLabel')}
      </Toast>
    );
  }

  if (toastType === ToastType.CannotEditMessage) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:ToastManager__CannotEditMessage_24')}
      </Toast>
    );
  }

  if (toastType === ToastType.CannotForwardEmptyMessage) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:ForwardMessagesModal__toast--CannotForwardEmptyMessage')}
      </Toast>
    );
  }

  if (toastType === ToastType.CannotMixMultiAndNonMultiAttachments) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:cannotSelectPhotosAndVideosAlongWithFiles')}
      </Toast>
    );
  }

  if (toastType === ToastType.CannotOpenGiftBadgeIncoming) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:message--donation--unopened--toast--incoming')}
      </Toast>
    );
  }

  if (toastType === ToastType.CannotOpenGiftBadgeOutgoing) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:message--donation--unopened--toast--outgoing')}
      </Toast>
    );
  }

  if (toastType === ToastType.CaptchaFailed) {
    return <Toast onClose={hideToast}>{i18n('icu:verificationFailed')}</Toast>;
  }

  if (toastType === ToastType.CaptchaSolved) {
    return (
      <Toast onClose={hideToast}>{i18n('icu:verificationComplete')}</Toast>
    );
  }

  if (toastType === ToastType.CannotStartGroupCall) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:GroupV2--cannot-start-group-call')}
      </Toast>
    );
  }

  if (toastType === ToastType.ChatFolderAddedChat) {
    return (
      <Toast onClose={hideToast}>
        <I18n
          i18n={i18n}
          id="icu:Toast--ChatFolderAddedChat"
          components={{
            chatFolderName: <UserText text={toast.parameters.chatFolderName} />,
          }}
        />
      </Toast>
    );
  }

  if (toastType === ToastType.ChatFolderRemovedChat) {
    return (
      <Toast onClose={hideToast}>
        <I18n
          i18n={i18n}
          id="icu:Toast--ChatFolderRemovedChat"
          components={{
            chatFolderName: <UserText text={toast.parameters.chatFolderName} />,
          }}
        />
      </Toast>
    );
  }

  if (toastType === ToastType.ChatFolderCreated) {
    return (
      <Toast onClose={hideToast}>
        <I18n
          i18n={i18n}
          id="icu:Toast--ChatFolderCreated"
          components={{
            chatFolderName: <UserText text={toast.parameters.chatFolderName} />,
          }}
        />
      </Toast>
    );
  }

  if (toastType === ToastType.ConversationArchived) {
    return (
      <Toast
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:conversationArchivedUndo'),
          onClick: () => {
            onUndoArchive(toast.parameters.conversationId, {
              wasPinned: toast.parameters.wasPinned,
            });
          },
        }}
      >
        {i18n('icu:conversationArchived')}
      </Toast>
    );
  }

  if (toastType === ToastType.ConversationMarkedUnread) {
    return (
      <Toast onClose={hideToast}>{i18n('icu:conversationMarkedUnread')}</Toast>
    );
  }

  if (toastType === ToastType.ConversationRemoved) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:Toast--ConversationRemoved', {
          title: toast.parameters.title,
        })}
      </Toast>
    );
  }

  if (toastType === ToastType.ConversationUnarchived) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:conversationReturnedToInbox')}
      </Toast>
    );
  }

  if (toastType === ToastType.CopiedBackupKey) {
    return (
      <Toast onClose={hideToast} timeout={3 * SECOND}>
        <div className={tw('flex items-center')}>
          <AxoSymbol.InlineGlyph symbol="copy" label={null} />
          &nbsp;&nbsp;
          {i18n('icu:Preferences__local-backups-copied-recovery-key')}
        </div>
      </Toast>
    );
  }

  if (toastType === ToastType.CopiedCallLink) {
    return (
      <Toast onClose={hideToast} timeout={3 * SECOND}>
        {i18n('icu:calling__call-link-copied')}
      </Toast>
    );
  }

  if (toastType === ToastType.CopiedStickerPackLink) {
    return (
      <Toast onClose={hideToast} timeout={3 * SECOND}>
        {i18n('icu:stickers--StickerPreview--LinkCopied')}
      </Toast>
    );
  }

  if (toastType === ToastType.CopiedUsername) {
    return (
      <Toast onClose={hideToast} timeout={3 * SECOND}>
        {i18n('icu:ProfileEditor--username--copied-username')}
      </Toast>
    );
  }

  if (toastType === ToastType.CopiedUsernameLink) {
    return (
      <Toast onClose={hideToast} timeout={3 * SECOND}>
        {i18n('icu:ProfileEditor--username--copied-username-link')}
      </Toast>
    );
  }

  if (toastType === ToastType.DangerousFileType) {
    return <Toast onClose={hideToast}>{i18n('icu:dangerousFileType')}</Toast>;
  }

  if (toastType === ToastType.DebugLogError) {
    return <Toast onClose={hideToast}>{i18n('icu:debugLogError')}</Toast>;
  }

  if (toastType === ToastType.DeleteForEveryoneFailed) {
    return (
      <Toast onClose={hideToast}>{i18n('icu:deleteForEveryoneFailed')}</Toast>
    );
  }

  if (toastType === ToastType.DonationCanceled) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:Donations__Toast__Canceled')}
      </Toast>
    );
  }

  if (toastType === ToastType.DonationCompleted) {
    return (
      <Toast
        autoDismissDisabled
        onClose={() => {
          hideToast();
        }}
        toastAction={{
          label: i18n('icu:view'),
          onClick: () =>
            changeLocation({
              tab: NavTab.Settings,
              details: {
                page: SettingsPage.Donations,
              },
            }),
        }}
      >
        {i18n('icu:Donations__Toast__Completed')}
      </Toast>
    );
  }

  if (toastType === ToastType.DonationProcessing) {
    return (
      <Toast
        onClose={() => {
          setDidResumeDonation(false);
          hideToast();
        }}
        toastAction={{
          label: i18n('icu:view'),
          onClick: () => {
            changeLocation({
              tab: NavTab.Settings,
              details: {
                page: SettingsPage.DonationsDonateFlow,
              },
            });
          },
        }}
      >
        {i18n('icu:Donations__Toast__Processing')}
      </Toast>
    );
  }

  if (
    toastType === ToastType.DonationCanceledWithView ||
    toastType === ToastType.DonationConfirmationNeeded ||
    toastType === ToastType.DonationError ||
    toastType === ToastType.DonationPaypalCanceled ||
    toastType === ToastType.DonationPaypalConfirmationNeeded ||
    toastType === ToastType.DonationPaypalError ||
    toastType === ToastType.DonationVerificationFailed ||
    toastType === ToastType.DonationVerificationNeeded
  ) {
    const mapping = {
      [ToastType.DonationCanceledWithView]: i18n(
        'icu:Donations__Toast__Canceled'
      ),
      [ToastType.DonationConfirmationNeeded]: i18n(
        'icu:Donations__Toast__ConfirmationNeeded'
      ),
      [ToastType.DonationError]: i18n('icu:Donations__Toast__Error'),
      [ToastType.DonationPaypalCanceled]: i18n(
        'icu:Donations__Toast__PaypalCanceled'
      ),
      [ToastType.DonationPaypalConfirmationNeeded]: i18n(
        'icu:Donations__Toast__PaypalConfirmationNeeded'
      ),
      [ToastType.DonationPaypalError]: i18n(
        'icu:Donations__Toast__PaypalError'
      ),
      [ToastType.DonationVerificationFailed]: i18n(
        'icu:Donations__Toast__VerificationFailed'
      ),
      [ToastType.DonationVerificationNeeded]: i18n(
        'icu:Donations__Toast__VerificationNeeded'
      ),
    };

    const pageRedirect =
      toastType === ToastType.DonationPaypalConfirmationNeeded
        ? SettingsPage.DonationsDonateFlow
        : SettingsPage.Donations;

    const text = mapping[toastType];

    return (
      <Toast
        autoDismissDisabled
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:view'),
          onClick: () => {
            changeLocation({
              tab: NavTab.Settings,
              details: {
                page: pageRedirect,
              },
            });
          },
        }}
      >
        {text}
      </Toast>
    );
  }

  if (toastType === ToastType.Error) {
    return (
      <Toast
        autoDismissDisabled
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:Toast--error--action'),
          onClick: () => window.IPC.showDebugLog(),
        }}
      >
        {i18n('icu:Toast--error')}
      </Toast>
    );
  }

  if (toastType === ToastType.UnableToDownloadFromBackupTier) {
    return (
      <Toast
        autoDismissDisabled
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:Toast--error--action'),
          onClick: () => window.IPC.showDebugLog(),
        }}
      >
        {i18n('icu:Toast--unable-download-from-backup-tier')}
      </Toast>
    );
  }

  if (toastType === ToastType.Expired) {
    return <Toast onClose={hideToast}>{i18n('icu:expiredWarning')}</Toast>;
  }

  if (toastType === ToastType.FailedToDeleteUsername) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:ProfileEditor--username--delete-general-error')}
      </Toast>
    );
  }

  if (toastType === ToastType.FailedToFetchPhoneNumber) {
    return (
      <Toast onClose={hideToast} style={{ maxWidth: '280px' }}>
        {i18n('icu:Toast--failed-to-fetch-phone-number')}
      </Toast>
    );
  }

  if (toastType === ToastType.FailedToFetchUsername) {
    return (
      <Toast onClose={hideToast} style={{ maxWidth: '280px' }}>
        {i18n('icu:Toast--failed-to-fetch-username')}
      </Toast>
    );
  }

  if (toastType === ToastType.FailedToImportBackup) {
    return (
      <Toast
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:Toast__ActionLabel--SubmitLog'),
          onClick: onShowDebugLog,
        }}
      >
        {i18n('icu:Toast--FailedToImportBackup')}
      </Toast>
    );
  }

  if (toastType === ToastType.InvalidStorageServiceHeaders) {
    return (
      <Toast
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:Toast__ActionLabel--SubmitLog'),
          onClick: onShowDebugLog,
        }}
      >
        {i18n('icu:Toast--InvalidStorageServiceHeaders')}
      </Toast>
    );
  }

  if (toastType === ToastType.FileSaved) {
    return (
      <Toast
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:attachmentSavedShow'),
          onClick: () => {
            openFileInFolder(toast.parameters.fullPath);
          },
        }}
      >
        {i18n('icu:attachmentSavedPlural', {
          count: toast.parameters.countOfFiles ?? 1,
        })}
      </Toast>
    );
  }

  if (toastType === ToastType.FileSize) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:fileSizeWarning', {
          limit: toast.parameters.limit,
          units: toast.parameters.units,
        })}
      </Toast>
    );
  }
  if (toastType === ToastType.VideoFileSize) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:videoFileSizeWarning', {
          limit: toast.parameters.limit,
          units: toast.parameters.units,
        })}
      </Toast>
    );
  }

  if (toastType === ToastType.GroupLinkCopied) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:GroupLinkManagement--clipboard')}
      </Toast>
    );
  }

  if (toastType === ToastType.DecryptionError) {
    assertDev(
      toast.toastType === ToastType.DecryptionError,
      'Pacify typescript'
    );
    const { parameters } = toast;
    const { deviceId, name } = parameters;

    return (
      <Toast
        autoDismissDisabled
        className="internal-error-toast"
        onClose={hideToast}
        style={{ maxWidth: '500px' }}
        toastAction={{
          label: i18n('icu:Toast__ActionLabel--SubmitLog'),
          onClick: onShowDebugLog,
        }}
      >
        {i18n('icu:decryptionErrorToast', {
          name,
          deviceId: String(deviceId),
        })}
      </Toast>
    );
  }

  if (toastType === ToastType.InvalidConversation) {
    return <Toast onClose={hideToast}>{i18n('icu:invalidConversation')}</Toast>;
  }

  if (toastType === ToastType.LeftGroup) {
    return <Toast onClose={hideToast}>{i18n('icu:youLeftTheGroup')}</Toast>;
  }

  if (toastType === ToastType.LinkCopied) {
    return <Toast onClose={hideToast}>{i18n('icu:debugLogLinkCopied')}</Toast>;
  }

  if (toastType === ToastType.LoadingFullLogs) {
    return <Toast onClose={hideToast}>{i18n('icu:loading')}</Toast>;
  }

  if (toastType === ToastType.MaxAttachments) {
    return <Toast onClose={hideToast}>{i18n('icu:maximumAttachments')}</Toast>;
  }

  if (toastType === ToastType.MediaNoLongerAvailable) {
    return <Toast onClose={hideToast}>{i18n('icu:mediaNotAvailable')}</Toast>;
  }

  if (toastType === ToastType.MessageBodyTooLong) {
    return <Toast onClose={hideToast}>{i18n('icu:messageBodyTooLong')}</Toast>;
  }

  if (toastType === ToastType.MessageLoop) {
    return (
      <Toast
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:Toast__ActionLabel--SubmitLog'),
          onClick: onShowDebugLog,
        }}
      >
        {i18n('icu:messageLoop')}
      </Toast>
    );
  }

  if (toastType === ToastType.NotificationProfileUpdate) {
    const { name, enabled } = toast.parameters;
    const text = enabled
      ? i18n('icu:NotificationProfilesToast--enabled', { name })
      : i18n('icu:NotificationProfilesToast--disabled', { name });
    const label = enabled
      ? i18n('icu:NotificationProfilesToast--enabled--label')
      : i18n('icu:NotificationProfilesToast--disabled--label');
    const symbol = enabled ? 'moon-fill' : 'moon-slash-fill';

    return (
      <Toast onClose={hideToast}>
        <div className={tw('flex items-center')}>
          <AxoSymbol.Icon symbol={symbol} size={12} label={label} />
          <span className={tw('mx-[10px]')}>{text}</span>
        </div>
      </Toast>
    );
  }

  if (toastType === ToastType.OriginalMessageNotFound) {
    return (
      <Toast onClose={hideToast}>{i18n('icu:originalMessageNotFound')}</Toast>
    );
  }

  if (toastType === ToastType.PinnedMessageNotFound) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:Toast--PinnedMessageNotFound')}
      </Toast>
    );
  }

  if (toastType === ToastType.PollNotFound) {
    return <Toast onClose={hideToast}>{i18n('icu:Toast--PollNotFound')}</Toast>;
  }

  if (toastType === ToastType._InternalMainProcessLoggingError) {
    return (
      <Toast
        autoDismissDisabled
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:Toast__ActionLabel--SubmitLog'),
          onClick: onShowDebugLog,
        }}
        // oxlint-disable-next-line better-tailwindcss/no-restricted-classes
        className={tw('max-w-[640px]!')}
      >
        <h2>
          [INTERNAL]: {toast.parameters.count} error(s) from main process,
          please submit log.
        </h2>

        {toast.parameters.count > toast.parameters.logLines.length ? (
          <h3
            className={tw('my-2')}
          >{`Showing only last ${toast.parameters.logLines.length} errors`}</h3>
        ) : null}

        <pre
          className={tw(
            'my-2 max-h-48 min-h-24 max-w-[520px] overflow-auto border border-solid p-2'
          )}
        >
          {toast.parameters.logLines.join('\n')}
        </pre>
      </Toast>
    );
  }

  if (toastType === ToastType._InternalHeapSizeWarning) {
    return (
      <Toast
        onClose={hideToast}
        toastAction={{
          label: 'Save Heap Snapshot',
          onClick: () => {
            saveHeapSnapshot();
          },
        }}
      >
        [INTERNAL] Detected high memory usage. Please save heap snapshot
        locally, and submit log.
      </Toast>
    );
  }

  if (toastType === ToastType.PinnedConversationsFull) {
    return (
      <Toast onClose={hideToast}>
        <I18n
          i18n={i18n}
          id="icu:pinnedConversations--max"
          components={{ maxPinnedConversations: toast.maxPinnedConversations }}
        />
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaRated) {
    // Literal English, like the rest of the persona UI: the demo strings are not in
    // _locales, and adding keys there means touching generated translation files.
    //
    // Worded to say what actually happened — a rating is a proof-carrying record, not a
    // reaction — because the absence of a visible reaction is the thing being explained.
    return (
      <Toast onClose={hideToast}>
        {toast.parameters.delta > 0
          ? 'Rated +1 as a persona (sent as a ZK record, not a reaction)'
          : 'Rated \u22121 as a persona (sent as a ZK record, not a reaction)'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaReactionBlocked) {
    return (
      <Toast onClose={hideToast}>
        {'Only \ud83d\udc4d / \ud83d\udc4e work on persona posts. Other reactions ' +
          'would be sent from your real account and link you to this post.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaSelfRateBlocked) {
    return (
      <Toast onClose={hideToast}>
        {'You cannot rate your own persona post \u2014 the protocol cannot detect ' +
          'self-rating, so it is declined here.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaViewsDiverged) {
    // Stays until dismissed, like a ban: it says something about every message in the
    // group, and a member who missed it would have no other way to learn it.
    return (
      <Toast onClose={hideToast}>
        {'Members of this group are not all seeing the same persona messages. ' +
          'Signal may have delayed or withheld some.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaRecordLost) {
    // Stays until dismissed: the member's post may still show on their own screen.
    return (
      <Toast onClose={hideToast}>
        {'Your last persona action did not reach the group. It arrived too late to ' +
          'count, so please send it again.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaBanned) {
    // No auto-dismiss timeout is passed, so this stays until dismissed. A ban changes
    // what the member can do in this group; a toast that vanished after four seconds
    // would be worse than none, because they would be left with a silently different UI
    // and no idea why.
    return (
      <Toast onClose={hideToast}>
        {'Your posts were flagged by a group admin. You have lost anonymous and ' +
          'pseudonymous posting in THIS group and can now only send messages under ' +
          'your real identity here. Other groups are unaffected.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaBadgeRequested) {
    return (
      <Toast onClose={hideToast}>
        {'Badge requested. A group admin has to approve it before you can use it.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaBadgeApproved) {
    // Says "will receive", not "has", on purpose: the approval invokes a callback at
    // the next settlement barrier, and the badge is only written into the requester's
    // object when THEY next scan. Claiming it is already granted would be wrong by
    // several seconds and one scan.
    return (
      <Toast onClose={hideToast}>
        {'Badge approved. The requester will receive it after their next scan.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaBadgeDismissed) {
    // Says what actually happened. "Denied" would imply the requester was refused;
    // nothing was sent, and they are still waiting.
    return (
      <Toast onClose={hideToast}>
        {'Request hidden from your queue. Nothing was sent \u2014 it is still pending ' +
          'for other admins.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaScanAbsorbed) {
    return (
      <Toast onClose={hideToast}>
        {`Scan absorbed your ${toast.parameters.gained} badge. You can now post ` +
          'under it and prove it.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaScanEmpty) {
    // Says what to do rather than just "nothing happened". An approval settles at the
    // next barrier, so a scan a moment too early legitimately finds nothing — and that
    // is the single most confusing moment in the badge flow.
    return (
      <Toast onClose={hideToast}>
        {'Nothing to absorb. If a badge was just approved for you, give it a few ' +
          'seconds to settle and scan again.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaBadgeProved) {
    return (
      <Toast onClose={hideToast}>
        {`Proved your ${toast.parameters.badge} badge in zero knowledge. The group can ` +
          'verify it without learning who you are.'}
      </Toast>
    );
  }

  if (toastType === ToastType.PersonaActionFailed) {
    // The reason is engine-authored text, shown verbatim. It is more use on screen,
    // even when it reads technically, than "Something went wrong" ever was.
    return (
      <Toast onClose={hideToast}>
        {`Persona action refused: ${toast.parameters.reason}`}
      </Toast>
    );
  }

  if (toastType === ToastType.ReactionFailed) {
    return <Toast onClose={hideToast}>{i18n('icu:Reactions--error')}</Toast>;
  }

  if (toastType === ToastType.ReceiptSaved) {
    return (
      <Toast
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:attachmentSavedShow'),
          onClick: () => {
            openFileInFolder(toast.parameters.fullPath);
          },
        }}
      >
        {i18n('icu:Toast--ReceiptSaved')}
      </Toast>
    );
  }

  if (toastType === ToastType.ReceiptSaveFailed) {
    return (
      <Toast onClose={hideToast}>{i18n('icu:Toast--ReceiptSaveFailed')}</Toast>
    );
  }

  if (toastType === ToastType.RemoteConfigChanged) {
    return (
      <Toast
        autoDismissDisabled
        onClose={hideToast}
        style={{ width: 'max-content', maxWidth: '650px' }}
      >
        <div>
          <strong>
            <span className={tw('text-warning')}>
              <AxoSymbol.InlineGlyph symbol="error-triangle" label="Change" />
            </span>
            &nbsp;Remote Config changed:
          </strong>
        </div>
        {toast.changes.map(({ name, from, to }) => (
          <div key={name} className={tw('font-mono type-body-small')}>
            {name}: {from} → {to}
          </div>
        ))}
      </Toast>
    );
  }

  if (toastType === ToastType.ReportedSpam) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:MessageRequests--report-spam-success-toast')}
      </Toast>
    );
  }

  if (toastType === ToastType.ReportedSpamAndBlocked) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:MessageRequests--block-and-report-spam-success-toast')}
      </Toast>
    );
  }

  if (toastType === ToastType.StickerPackInstallFailed) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:stickers--toast--InstallFailed')}
      </Toast>
    );
  }
  if (toastType === ToastType.SQLError) {
    return (
      <Toast
        onClose={hideToast}
        toastAction={{
          label: i18n('icu:Toast__ActionLabel--SubmitLog'),
          onClick: onShowDebugLog,
        }}
        autoDismissDisabled
      >
        {i18n('icu:Toast--SQLError')}
      </Toast>
    );
  }

  if (toastType === ToastType.StoryMuted) {
    return (
      <Toast onClose={hideToast} timeout={SHORT_TIMEOUT}>
        {i18n('icu:Stories__toast--hasNoSound')}
      </Toast>
    );
  }

  if (toastType === ToastType.StoryReact) {
    return (
      <Toast onClose={hideToast} timeout={SHORT_TIMEOUT}>
        {i18n('icu:Stories__toast--sending-reaction')}
      </Toast>
    );
  }

  if (toastType === ToastType.StoryReply) {
    return (
      <Toast onClose={hideToast} timeout={SHORT_TIMEOUT}>
        {i18n('icu:Stories__toast--sending-reply')}
      </Toast>
    );
  }

  if (toastType === ToastType.StoryVideoError) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:StoryCreator__error--video-error')}
      </Toast>
    );
  }

  if (toastType === ToastType.StoryVideoUnsupported) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:StoryCreator__error--video-unsupported')}
      </Toast>
    );
  }

  if (toastType === ToastType.TapToViewExpiredIncoming) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:Message--tap-to-view--incoming--expired-toast')}
      </Toast>
    );
  }

  if (toastType === ToastType.TapToViewExpiredOutgoing) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:Message--tap-to-view--outgoing--expired-toast-2')}
      </Toast>
    );
  }

  if (toastType === ToastType.TooManyMessagesToDeleteForEveryone) {
    return (
      <Toast onClose={hideToast}>
        {i18n(
          'icu:DeleteMessagesModal__toast--TooManyMessagesToDeleteForEveryone',
          { count: toast.parameters.count }
        )}
      </Toast>
    );
  }

  if (toastType === ToastType.TooManyMessagesToForward) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:SelectModeActions__toast--TooManyMessagesToForward')}
      </Toast>
    );
  }

  if (toastType === ToastType.TransportError) {
    return <Toast onClose={hideToast}>{i18n('icu:TransportError')}</Toast>;
  }

  if (toastType === ToastType.UnableToLoadAttachment) {
    return (
      <Toast onClose={hideToast}>{i18n('icu:unableToLoadAttachment')}</Toast>
    );
  }

  if (toastType === ToastType.UnsupportedMultiAttachment) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:cannotSelectMultipleFileAttachments')}
      </Toast>
    );
  }

  if (toastType === ToastType.UnsupportedOS) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:UnsupportedOSErrorToast', { OS })}
      </Toast>
    );
  }

  if (toastType === ToastType.UsernameRecovered) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:EditUsernameModalBody__username-recovered__text', {
          username: toast.parameters.username,
        })}
      </Toast>
    );
  }

  if (toastType === ToastType.UserAddedToGroup) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:AddUserToAnotherGroupModal__toast--user-added-to-group', {
          contact: toast.parameters.contact,
          group: toast.parameters.group,
        })}
      </Toast>
    );
  }

  if (toastType === ToastType.VoiceNoteLimit) {
    return <Toast onClose={hideToast}>{i18n('icu:voiceNoteLimit')}</Toast>;
  }

  if (toastType === ToastType.VoiceNoteMustBeTheOnlyAttachment) {
    return (
      <Toast onClose={hideToast}>
        {i18n('icu:voiceNoteMustBeOnlyAttachment')}
      </Toast>
    );
  }

  if (toastType === ToastType.WhoCanFindMeReadOnly) {
    return (
      <Toast onClose={hideToast}>{i18n('icu:WhoCanFindMeReadOnlyToast')}</Toast>
    );
  }

  if (toastType === ToastType.ViewOnceEnabled) {
    return (
      <Toast onClose={hideToast} timeout={SHORT_TIMEOUT}>
        {i18n('icu:Toast--viewOnceEnabled')}
      </Toast>
    );
  }

  if (toastType === ToastType.ViewOnceDisabled) {
    return (
      <Toast onClose={hideToast} timeout={SHORT_TIMEOUT}>
        {i18n('icu:Toast--viewOnceDisabled')}
      </Toast>
    );
  }

  throw missingCaseError(toastType);
}

function renderMegaphone({
  i18n,
  megaphone,
  containerWidthBreakpoint,
  expandNarrowLeftPane,
}: PropsType): JSX.Element | null {
  if (!megaphone) {
    return null;
  }

  if (megaphone.type === MegaphoneType.UsernameOnboarding) {
    return <UsernameMegaphone i18n={i18n} {...megaphone} />;
  }

  if (megaphone.type === MegaphoneType.Remote) {
    return (
      <RemoteMegaphone
        {...megaphone}
        i18n={i18n}
        isFullSize={containerWidthBreakpoint !== WidthBreakpoint.Narrow}
        onClickNarrowMegaphone={expandNarrowLeftPane}
      />
    );
  }

  throw missingCaseError(megaphone);
}

export function ToastManager(props: PropsType): JSX.Element {
  const {
    centerToast,
    containerWidthBreakpoint,
    isCompositionAreaVisible,
    isInFullScreenCall,
    megaphone,
  } = props;

  const toast = renderToast(props);

  return (
    <div className="ToastManagerContainer">
      <div
        className={classNames('ToastManager', {
          'ToastManager--narrow-sidebar':
            containerWidthBreakpoint === WidthBreakpoint.Narrow,
          'ToastManager--composition-area-visible': isCompositionAreaVisible,
        })}
      >
        {centerToast
          ? createPortal(
              <div
                className={classNames('ToastManager__root', {
                  'ToastManager--full-screen-call': isInFullScreenCall,
                })}
              >
                {toast}
              </div>,
              document.body
            )
          : toast}
      </div>
      {megaphone && (
        <div
          className={classNames('ToastManager', 'ToastManager--megaphones', {
            'ToastManager--narrow-sidebar':
              containerWidthBreakpoint === WidthBreakpoint.Narrow,
          })}
        >
          {renderMegaphone(props)}
        </div>
      )}
    </div>
  );
}
