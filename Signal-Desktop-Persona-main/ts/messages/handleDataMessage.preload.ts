// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import lodash from 'lodash';
import type { z } from 'zod';

import { createLogger } from '../logging/log.std.ts';
import {
  isAttributableRecord,
  ingestRecordForTimeline,
  verifyPersonaAuthorship,
  verifyPersonaBadgeProof,
  waitForPersonasEngineIfStarting,
} from '../services/personasEngine.preload.ts';
import {
  decodePostText,
  decodeAuthorshipProof,
  decodeBadgeProof,
  decodeRecordBody,
  decodeRelayBody,
  decodeResetRequest,
  decodeCatchUpPart,
  isCatchUpRequest,
  isPersonasCarriage,
} from '../services/personasCarriage.std.ts';
import {
  ingestResetRequest,
  recordSenderProblem,
} from '../services/personasReset.preload.ts';
import { trackPersonaPost } from '../services/personasRegistry.std.ts';
import {
  answerCatchUpRequest,
  requestCatchUpIfNeeded,
  ingestCatchUpPart,
} from '../services/personasCatchUp.preload.ts';
import { recordTimestamp } from '../services/personasBarrier.preload.ts';
import {
  decodePhantomBundle,
  decodeTopicAnnouncement,
} from '../services/personasCarriage.std.ts';
import {
  adoptPhantomBundle,
  holdPendingBundle,
  isFellowGroupMember,
  isPersonasGroup,
} from '../services/personasPhantom.preload.ts';
import {
  ingestTopicAnnouncement,
  verifiedContextName,
} from '../services/personasTopics.preload.ts';
import { getPhantomAci } from '../services/personasPhantom.preload.ts';
import * as Errors from '../types/errors.std.ts';

import { isStory } from './helpers.std.ts';
import { getAuthor } from './sources.preload.ts';
import { messageHasPaymentEvent } from './payments.std.ts';
import { getMessageIdForLogging } from '../util/idForLogging.preload.ts';
import {
  deliveryReceiptQueue,
  deliveryReceiptBatcher,
} from '../util/deliveryReceipt.preload.ts';
import { upgradeMessageSchema } from '../util/migrations.preload.ts';
import { getOwn } from '../util/getOwn.std.ts';
import {
  SendActionType,
  sendStateReducer,
  SendStatus,
} from './MessageSendState.std.ts';
import { DataReader, DataWriter } from '../sql/Client.preload.ts';
import { eraseMessageContents } from '../util/cleanup.preload.ts';
import {
  isDirectConversation,
  isGroup,
  isGroupV1,
  isGroupV2,
} from '../util/whatTypeOfConversation.dom.ts';
import {
  respondToGroupV2Migration,
  maybeUpdateGroup,
} from '../groups.preload.ts';
import { generateMessageId } from '../util/generateMessageId.node.ts';
import {
  hasErrors,
  isEndSession,
  isExpirationTimerUpdate,
  isGroupUpdate,
  isTapToView,
  isUnsupportedMessage,
} from '../state/selectors/message.preload.ts';
import { drop } from '../util/drop.std.ts';
import { strictAssert } from '../util/assert.std.ts';
import { isAciString } from '../util/isAciString.std.ts';
import { copyFromQuotedMessage } from './copyQuote.preload.ts';
import { findStoryMessage } from '../util/findStoryMessage.preload.ts';
import { getValidLinkPreviews } from '../util/getValidLinkPreviews.node.ts';
import { normalizeServiceId } from '../types/ServiceId.std.ts';
import { BodyRange, trimMessageWhitespace } from '../types/BodyRange.std.ts';
import { hydrateStoryContext } from '../util/hydrateStoryContext.preload.ts';
import { isMessageEmpty } from '../util/isMessageEmpty.preload.ts';
import { isValidTapToView } from '../util/isValidTapToView.std.ts';
import { getNotificationTextForMessage } from '../util/getNotificationTextForMessage.preload.ts';
import {
  getMessageAuthorAci,
  getMessageAuthorText,
} from '../util/getMessageAuthorText.preload.ts';
import { GiftBadgeStates } from '../types/GiftBadgeStates.std.ts';
import { parseBoostBadgeListFromServer } from '../badges/parseBadgesFromServer.std.ts';
import { SignalService as Proto } from '../protobuf/index.std.ts';
import {
  modifyTargetMessage,
  ModifyTargetMessageResult,
} from '../util/modifyTargetMessage.preload.ts';
import type { saveAndNotify } from './saveAndNotify.preload.ts';
import type { MessageModel } from '../models/messages.preload.ts';
import { safeParsePartial } from '../util/schemas.std.ts';
import { PollCreateSchema } from '../types/Polls.dom.ts';

import type { SentEventData } from '../textsecure/messageReceiverEvents.std.ts';
import type {
  ProcessedDataMessage,
  ProcessedUnidentifiedDeliveryStatus,
} from '../textsecure/Types.d.ts';
import type { ServiceIdString } from '../types/ServiceId.std.ts';
import { getCachedSubscriptionConfiguration } from '../util/subscriptionConfiguration.preload.ts';
import { itemStorage } from '../textsecure/Storage.preload.ts';

const { isNumber } = lodash;

const log = createLogger('handleDataMessage');

const CURRENT_PROTOCOL_VERSION = Proto.DataMessage.ProtocolVersion.CURRENT;
const INITIAL_PROTOCOL_VERSION = Proto.DataMessage.ProtocolVersion.INITIAL;

export async function handleDataMessage(
  message: MessageModel,
  initialMessage: ProcessedDataMessage,
  confirm: () => void,
  options: { data?: SentEventData } = {},
  dependencies: {
    saveAndNotify: typeof saveAndNotify;
  }
): Promise<void> {
  const { data } = options;

  // This function is called from the background script in a few scenarios:
  //   1. on an incoming message
  //   2. on a sent message sync'd from another device
  //   3. in rare cases, an incoming message can be retried, though it will
  //      still go through one of the previous two codepaths
  const source = message.get('source');
  const sourceServiceId = message.get('sourceServiceId');
  const type = message.get('type');
  const conversationId = message.get('conversationId');

  const fromContact = getAuthor(message.attributes);
  if (fromContact) {
    fromContact.setRegistered();
  }

  // oxlint-disable-next-line typescript/no-non-null-assertion
  const conversation = window.ConversationController.get(conversationId)!;
  const idLog = `handleDataMessage/${conversation.idForLogging()} ${getMessageIdForLogging(message.attributes)}`;
  await conversation.queueJob(idLog, async () => {
    log.info(`${idLog}: starting processing in queue`);

    // Personas demo (Phase 4): if this body carries a ZK record, ingest it into the
    // engine now (verify + fold). A protocol record (join/vote/rate/scan) is folded
    // with no timeline entry — drop it here. A post or a poll is stashed and applied
    // to the message below, once its body has been populated from the wire.
    // Non-records fall straight through. `initialMessage.body` is the authoritative
    // incoming body.
    //
    // Phase 6: pass the SERVICE timestamp, not 0. On the shared barrier schedule that
    // is what buckets this record onto a barrier every member agrees about, which is
    // what makes settlement (and therefore ban) converge across instances — see
    // personasBarrier.
    // A topic announcement is coordination metadata, not a ZK record: fold it into
    // the topic registry and drop it. It must be handled BEFORE the record path,
    // because it carries no proof and the engine would reject it.
    // An authorship claim is now a real ZK PROOF, verified here before it is shown.
    //
    // It is still not a record: nothing is folded into the replica and no accept rule
    // applies. But it is no longer an assertion either — `verifyPersonaAuthorship`
    // checks the Groth16 proof against `authorship_pred`'s verifying key.
    //
    // THE NAMES COME FROM THE VERIFIER, NOT THE MESSAGE. The wire carries only the
    // proof (see encodeAuthorshipProof), and the petnames are derived from the proof's
    // own public inputs. That ordering is the security property: a sender holding a
    // valid proof about two pseudonyms they genuinely own could otherwise display it
    // beside someone else's persona names, and the checkmark would be true while the
    // statement was false.
    //
    // A proof that does not verify is DROPPED, not shown as unverified. An
    // unverifiable authorship message has no legitimate sender, so rendering it at all
    // would only give a forger a surface.
    // A PHANTOM BUNDLE (1:1, key material): adopt it if it comes from a fellow member of
    // one of our groups, then drop the message before anything saves its body. First
    // checked, so no other path ever sees the key material.
    // PERSONAS ARE PER GROUP. Each personas group has its own engine; personas traffic
    // in a group this app has no bundle for — its records, topics, proofs, requests —
    // belongs to an engine this app does not run, so it is dropped rather than ingested
    // here or shown as raw text.
    const personasGroupId = conversation.get('groupId');
    if (
      isGroupV2(conversation.attributes) &&
      isPersonasCarriage(initialMessage.body) &&
      !isPersonasGroup(conversation)
    ) {
      log.info(`${idLog}: personas traffic in a group personas are not on in; dropped`);
      confirm();
      return;
    }

    const phantomBundle = decodePhantomBundle(initialMessage.body);
    if (phantomBundle) {
      const from = sourceServiceId ?? source ?? 'unknown';
      if (isFellowGroupMember(conversationId, phantomBundle.groupId)) {
        const result = await adoptPhantomBundle(phantomBundle, from);
        log.info(`${idLog}: phantom bundle from ${from}: ${result}`);
        if (result === 'full') {
          // At this account's group limit: kept, adopted once it leaves a group.
          holdPendingBundle(conversationId, phantomBundle, from);
        }
      } else {
        // Possibly just ahead of the group update that adds us; re-checked each sweep.
        holdPendingBundle(conversationId, phantomBundle, from);
      }
      confirm();
      return;
    }

    const authorshipProof = decodeAuthorshipProof(initialMessage.body);
    if (authorshipProof) {
      const verified = verifyPersonaAuthorship(personasGroupId, authorshipProof);
      if (!verified) {
        log.warn(
          `${idLog}: authorship proof FAILED verification; dropping the message`
        );
        confirm();
        return;
      }
      message.set({
        body: undefined,
        // ANONYMOUS. The proof's whole claim is "these two pseudonyms share an author"
        // — it says nothing about WHICH author, and it is not supposed to. Attributing
        // the bubble to the sender's real name answered, for free, the one question the
        // proof deliberately leaves open. The proof now rides the phantom too (PZU2 is
        // in PHANTOM_MARKERS), so this label matches what is actually on the wire.
        personaAnonymous: true,
        personaAuthorship: {
          first: verified.first,
          second: verified.second,
          verified: true,
        },
      });
      log.info(
        `${idLog}: authorship proof verified: ${verified.first} = ${verified.second}`
      );
    }

    // A BADGE POSSESSION PROOF. Same treatment as authorship, and for the same reasons:
    // verified here, dropped if it fails, and the badge NAME is taken from the
    // verifier's output rather than from anything in the message. A sender holding a
    // valid Industry proof must not be able to render it as Faculty.
    const badgeProof = decodeBadgeProof(initialMessage.body);
    if (badgeProof) {
      const provenBadge = verifyPersonaBadgeProof(personasGroupId, badgeProof);
      if (!provenBadge) {
        log.warn(
          `${idLog}: badge proof FAILED verification; dropping the message`
        );
        confirm();
        return;
      }
      message.set({
        body: undefined,
        // Anonymous: the proof establishes that SOMEONE here holds the badge, not who.
        // The envelope agrees — it rides the phantom — so this label is not a veneer.
        personaAnonymous: true,
        personaBadgeProof: { badge: provenBadge, verified: true },
      });
      log.info(`${idLog}: badge proof verified: holds ${provenBadge}`);
    }

    const topicAnnouncement = decodeTopicAnnouncement(initialMessage.body);
    if (topicAnnouncement && personasGroupId) {
      ingestTopicAnnouncement(personasGroupId, topicAnnouncement);
      log.info(`${idLog}: personas topic announcement ingested`);
      confirm();
      return;
    }

    // LATE-JOIN CATCH-UP (personasCatchUp): a member's request for the group state, to
    // the group (an admin's app answers it), and the parts of an admin's answer, 1:1.
    // Coordination only, never rendered.
    if (isCatchUpRequest(initialMessage.body)) {
      await waitForPersonasEngineIfStarting(personasGroupId);
      await answerCatchUpRequest(conversation, sourceServiceId);
      confirm();
      return;
    }
    const catchUpPart = decodeCatchUpPart(initialMessage.body);
    if (catchUpPart) {
      // 1:1, so the group comes from the part itself.
      await waitForPersonasEngineIfStarting(catchUpPart.g);
      ingestCatchUpPart(catchUpPart, sourceServiceId);
      confirm();
      return;
    }

    // A RESET REQUEST (personasReset): coordination for admins, never rendered.
    const resetRequest = decodeResetRequest(initialMessage.body);
    if (resetRequest) {
      await waitForPersonasEngineIfStarting(personasGroupId);
      ingestResetRequest(personasGroupId, resetRequest, sourceServiceId);
      confirm();
      return;
    }

    // A record that arrives while the engine is still starting waits for it rather
    // than being dropped (a dropped record forks this member off the group).
    if (
      decodeRecordBody(initialMessage.body) ||
      decodeRelayBody(initialMessage.body)
    ) {
      await waitForPersonasEngineIfStarting(personasGroupId);
      // A member added late asks for the group state (without waiting for it: a record
      // the engine cannot apply yet is held and shown once it applies).
      requestCatchUpIfNeeded(conversation);
      // A join must come from the account it names, and a re-join approval from a
      // group admin. Dropped otherwise, before the engine sees it (personasReset).
      const senderProblem = recordSenderProblem(
        initialMessage.body,
        sourceServiceId,
        conversation
      );
      if (senderProblem) {
        log.warn(`${idLog}: personas record dropped: ${senderProblem}`);
        confirm();
        return;
      }
    }
    // For checking that every member sees the same service timestamp on a record.
    const incomingRecord = decodeRecordBody(initialMessage.body);
    if (incomingRecord) {
      log.info(
        `personas stamp: record …${incomingRecord.toString('base64').slice(-16)} ` +
          `sent_at=${message.get('sent_at')} server=${message.get('serverTimestamp')}`
      );
    }
    const personasRecord = ingestRecordForTimeline(
      personasGroupId,
      initialMessage.body,
      recordTimestamp(
        message.get('sent_at'),
        message.get('serverTimestamp'),
        isAttributableRecord(personasGroupId, initialMessage.body)
      )
    );
    if (personasRecord.kind === 'ingested') {
      log.info(`${idLog}: personas protocol record ingested (no timeline entry)`);
      confirm();
      return;
    }

    // First, check for duplicate messages. We dedupe by senderAci + timestamp, in the
    // same way we address messages in the Signal ecosystem.
    const existingMessage = await window.MessageCache.findBySentAt(
      message.attributes.sent_at,
      msg => msg.attributes.sourceServiceId === sourceServiceId
    );

    const isUpdate = Boolean(data && data.isRecipientUpdate);

    const isDuplicateMessage =
      existingMessage &&
      (type === 'incoming' ||
        (type === 'story' &&
          existingMessage.get('storyDistributionListId') ===
            message.attributes.storyDistributionListId));

    if (isDuplicateMessage) {
      log.warn(
        `${idLog}: Received duplicate message`,
        getMessageIdForLogging(message.attributes)
      );
      confirm();
      return;
    }

    if (type === 'outgoing') {
      if (isUpdate && existingMessage) {
        log.info(
          `${idLog}: Updating message ${getMessageIdForLogging(message.attributes)} with received transcript`
        );

        const toUpdate = window.MessageCache.register(existingMessage);

        const unidentifiedDeliveriesSet = new Set<string>(
          toUpdate.get('unidentifiedDeliveries') ?? []
        );
        const sendStateByConversationId = {
          ...toUpdate.get('sendStateByConversationId'),
        };

        const unidentifiedStatus: Array<ProcessedUnidentifiedDeliveryStatus> =
          data && Array.isArray(data.unidentifiedStatus)
            ? data.unidentifiedStatus
            : [];

        unidentifiedStatus.forEach(({ destinationServiceId, unidentified }) => {
          if (!destinationServiceId) {
            return;
          }

          const destinationConversation =
            window.ConversationController.lookupOrCreate({
              serviceId: destinationServiceId,
              reason: `handleDataMessage(${initialMessage.timestamp})`,
            });
          if (!destinationConversation) {
            return;
          }

          const updatedAt: number = data?.timestamp ?? Date.now();

          const previousSendState = getOwn(
            sendStateByConversationId,
            destinationConversation.id
          );
          sendStateByConversationId[destinationConversation.id] =
            previousSendState
              ? sendStateReducer(previousSendState, {
                  type: SendActionType.Sent,
                  updatedAt,
                })
              : {
                  status: SendStatus.Sent,
                  updatedAt,
                };

          if (unidentified) {
            unidentifiedDeliveriesSet.add(destinationServiceId);
          }
        });

        toUpdate.set({
          sendStateByConversationId,
          unidentifiedDeliveries: [...unidentifiedDeliveriesSet],
        });
        await window.MessageCache.saveMessage(toUpdate.attributes);

        confirm();
        return;
      }
      if (isUpdate) {
        log.warn(
          `${idLog}: Received update transcript, but no existing entry for message ${getMessageIdForLogging(message.attributes)}. Dropping.`
        );

        confirm();
        return;
      }
      if (existingMessage) {
        // TODO: (DESKTOP-7301): improve this check in case previous message is not yet
        // registered in memory
        log.warn(
          `${idLog}: Received duplicate transcript for message ${getMessageIdForLogging(message.attributes)}, but it was not an update transcript. Dropping.`
        );

        confirm();
        return;
      }
    }

    // GroupV2
    if (initialMessage.groupV2) {
      if (isGroupV1(conversation.attributes)) {
        // If we received a GroupV2 message in a GroupV1 group, we migrate!

        const { revision, groupChange } = initialMessage.groupV2;
        await respondToGroupV2Migration({
          conversation,
          groupChange: groupChange
            ? {
                base64: groupChange,
                isTrusted: false,
              }
            : undefined,
          newRevision: revision,
          receivedAt: message.get('received_at'),
          sentAt: message.get('sent_at'),
        });
      } else if (
        initialMessage.groupV2.masterKey &&
        initialMessage.groupV2.secretParams &&
        initialMessage.groupV2.publicParams
      ) {
        // Repair core GroupV2 data if needed
        conversation.maybeRepairGroupV2({
          masterKey: initialMessage.groupV2.masterKey,
          secretParams: initialMessage.groupV2.secretParams,
          publicParams: initialMessage.groupV2.publicParams,
        });

        const existingRevision = conversation.get('revision');
        const isFirstUpdate = !isNumber(existingRevision);

        // Standard GroupV2 modification codepath
        const isV2GroupUpdate =
          initialMessage.groupV2 &&
          isNumber(initialMessage.groupV2.revision) &&
          (isFirstUpdate || initialMessage.groupV2.revision > existingRevision);

        if (isV2GroupUpdate && initialMessage.groupV2) {
          const { revision, groupChange } = initialMessage.groupV2;
          try {
            await maybeUpdateGroup({
              conversation,
              groupChange: groupChange
                ? {
                    base64: groupChange,
                    isTrusted: false,
                  }
                : undefined,
              newRevision: revision,
              receivedAt: message.get('received_at'),
              sentAt: message.get('sent_at'),
              serverGuid: message.get('serverGuid'),
            });
          } catch (error) {
            const errorText = Errors.toLogFormat(error);
            log.error(
              `${idLog}: Failed to process group update as part of message ${getMessageIdForLogging(message.attributes)}: ${errorText}`
            );
            throw error;
          }
        }
      }
    }

    const ourAci = itemStorage.user.getCheckedAci();
    // oxlint-disable-next-line typescript/no-non-null-assertion
    const sender = window.ConversationController.lookupOrCreate({
      e164: source,
      serviceId: sourceServiceId,
      reason: 'handleDataMessage',
    })!;
    const hasGroupV2Prop = Boolean(initialMessage.groupV2);

    // Drop if from blocked user. Only GroupV2 messages should need to be dropped here.
    const isBlocked =
      (source && itemStorage.blocked.isBlocked(source)) ||
      (sourceServiceId &&
        itemStorage.blocked.isServiceIdBlocked(sourceServiceId));
    if (isBlocked) {
      log.info(
        `${idLog}: Dropping message from blocked sender. hasGroupV2Prop: ${hasGroupV2Prop}`
      );

      confirm();
      return;
    }

    const areWeMember = conversation.areWeAGroupMember();

    // Drop an incoming GroupV2 message if we or the sender are not part of the group
    //   after applying the message's associated group changes.
    if (
      type === 'incoming' &&
      !isDirectConversation(conversation.attributes) &&
      hasGroupV2Prop &&
      // Personas Phase 5: a persona post is sealed under the shared phantom identity,
      // which is deliberately NOT a group member. Exempt it from the sender-membership
      // drop (we still drop if WE are not a member). The phantom ACI is a fixed
      // reserved UUID no real account uses, so this is inert outside the demo.
      (!areWeMember ||
        (sourceServiceId &&
          sourceServiceId !== getPhantomAci() &&
          !conversation.hasMember(sourceServiceId)))
    ) {
      log.warn(
        `${idLog}: Received message destined for group, which we or the sender are not a part of. Dropping.`
      );
      confirm();
      return;
    }

    // We drop incoming messages for v1 groups we already know about, which we're not
    //   a part of, except for group updates. Because group v1 updates haven't been
    //   applied by this point.
    // Note: if we have no information about a group at all, we will accept those
    //   messages. We detect that via a missing 'members' field.
    if (
      type === 'incoming' &&
      !isDirectConversation(conversation.attributes) &&
      !hasGroupV2Prop &&
      conversation.get('members') &&
      !areWeMember
    ) {
      log.warn(
        `Received message destined for group ${conversation.idForLogging()}, which we're not a part of. Dropping.`
      );
      confirm();
      return;
    }

    // Drop incoming messages to announcement only groups where sender is not admin
    if (conversation.get('announcementsOnly')) {
      const senderServiceId = sender.getServiceId();
      if (!senderServiceId || !conversation.isAdmin(senderServiceId)) {
        confirm();
        return;
      }
    }

    const messageId =
      message.get('id') || generateMessageId(message.get('received_at')).id;

    // Send delivery receipts, but only for non-story sealed sender messages
    //   and not for messages from unaccepted conversations
    if (
      type === 'incoming' &&
      message.get('unidentifiedDeliveryReceived') &&
      !hasErrors(message.attributes) &&
      conversation.getAccepted()
    ) {
      // Note: We both queue and batch because we want to wait until we are done
      //   processing incoming messages to start sending outgoing delivery receipts.
      //   The queue can be paused easily.
      drop(
        deliveryReceiptQueue.add(() => {
          strictAssert(
            isAciString(sourceServiceId),
            'Incoming message must be from ACI'
          );
          deliveryReceiptBatcher.add({
            messageId,
            conversationId,
            senderE164: source,
            senderAci: sourceServiceId,
            timestamp: message.get('sent_at'),
            isDirectConversation: isDirectConversation(conversation.attributes),
          });
        })
      );
    }

    // Drop incoming messages to terminated groups
    if (conversation.get('terminated')) {
      log.warn(
        `Received message for terminated group ${conversation.idForLogging()}. Dropping.`
      );
      confirm();
      return;
    }

    const { storyContext } = initialMessage;
    let storyContextLogId = 'no storyContext';
    if (storyContext) {
      storyContextLogId =
        `storyContext(${storyContext.sentTimestamp}, ` +
        `${storyContext.authorAci})`;
    }

    // Ensure that quote author's conversation exist
    if (initialMessage.quote) {
      window.ConversationController.lookupOrCreate({
        serviceId: initialMessage.quote.authorAci,
        reason: 'handleDataMessage.quote.author',
      });
    }

    const [quote, storyQuote] = await Promise.all([
      initialMessage.quote
        ? copyFromQuotedMessage(initialMessage.quote, conversation.id)
        : undefined,
      findStoryMessage({
        conversation: conversation.attributes,
        senderId: sender.id,
        storyContext,
      }),
    ]);

    if (
      storyContext &&
      !storyQuote &&
      !isDirectConversation(conversation.attributes)
    ) {
      log.warn(
        `${idLog}: Received ${storyContextLogId} message in group but no matching story. Dropping.`
      );

      confirm();
      return;
    }

    if (storyQuote) {
      const { storyDistributionListId } = storyQuote;

      if (storyDistributionListId) {
        const storyDistribution =
          await DataReader.getStoryDistributionWithMembers(
            storyDistributionListId
          );

        if (!storyDistribution) {
          log.warn(
            `${idLog}: Received ${storyContextLogId} message for story with no associated distribution list. Dropping.`
          );

          confirm();
          return;
        }

        if (!storyDistribution.allowsReplies) {
          log.warn(
            `${idLog}: Received ${storyContextLogId} message but distribution list does not allow replies. Dropping.`
          );

          confirm();
          return;
        }
      }
    }

    let validatedPollCreate: z.infer<typeof PollCreateSchema> | undefined;
    if (initialMessage.pollCreate) {
      const result = safeParsePartial(
        PollCreateSchema,
        initialMessage.pollCreate
      );
      if (!result.success) {
        log.warn(
          `${idLog}: Dropping invalid PollCreate:`,
          result.error.flatten()
        );
        confirm();
        return;
      }
      validatedPollCreate = result.data;
    }

    const withQuoteReference = {
      ...message.attributes,
      ...initialMessage,
      quote,
      storyId: storyQuote?.id,
    };

    // There are type conflicts between ModelAttributesType and protos passed in here
    // oxlint-disable-next-line typescript/no-explicit-any
    const dataMessage = await upgradeMessageSchema(withQuoteReference as any);

    const isGroupStoryReply =
      isGroup(conversation.attributes) && dataMessage.storyId;

    try {
      const now = new Date().getTime();
      const incomingPreview = dataMessage.preview || [];

      const preview = getValidLinkPreviews(incomingPreview, dataMessage.body, {
        isStory: isStory(message.attributes),
      });

      if (preview.length < incomingPreview.length) {
        log.warn(
          `${getMessageIdForLogging(message.attributes)}: Eliminated ${
            incomingPreview.length - preview.length
          } previews with invalid urls`
        );
      }

      const ourPni = itemStorage.user.getCheckedPni();
      const ourServiceIds = new Set<ServiceIdString>([ourAci, ourPni]);

      // oxlint-disable-next-line no-param-reassign
      message = window.MessageCache.register(message);

      message.set({
        id: messageId,
        attachments: dataMessage.attachments,
        bodyAttachment: dataMessage.bodyAttachment,
        // We don't want to trim if we'll be downloading a body attachment; we might
        // drop bodyRanges which apply to the longer text we'll get in that download.
        ...(dataMessage.bodyAttachment
          ? {
              body: dataMessage.body,
              bodyRanges: dataMessage.bodyRanges,
            }
          : trimMessageWhitespace({
              body: dataMessage.body,
              bodyRanges: dataMessage.bodyRanges,
            })),
        contact: dataMessage.contact,
        conversationId: conversation.id,
        decrypted_at: now,
        errors: [],
        flags: dataMessage.flags,
        giftBadge: initialMessage.giftBadge,
        isViewOnce: Boolean(dataMessage.isViewOnce),
        mentionsMe: (dataMessage.bodyRanges ?? []).some(bodyRange => {
          if (!BodyRange.isMention(bodyRange)) {
            return false;
          }
          return ourServiceIds.has(
            normalizeServiceId(
              bodyRange.mentionAci,
              'handleDataMessage: mentionsMe check'
            )
          );
        }),
        preview,
        requiredProtocolVersion:
          dataMessage.requiredProtocolVersion || INITIAL_PROTOCOL_VERSION,
        supportedVersionAtReceive: CURRENT_PROTOCOL_VERSION,
        payment: dataMessage.payment,
        quote: dataMessage.quote,
        schemaVersion: dataMessage.schemaVersion,
        sticker: dataMessage.sticker,
        poll: validatedPollCreate
          ? {
              question: validatedPollCreate.question,
              options: validatedPollCreate.options,
              allowMultiple: Boolean(validatedPollCreate.allowMultiple),
              votes: [],
            }
          : undefined,
        storyId: dataMessage.storyId,
      });

      // Personas demo (Phase 4): now that the incoming record body is on the model,
      // replace it with the post's plaintext and attribute it to the persona. The
      // record was already ingested above; this only rewrites what is displayed.
      //
      // Phase 6 additions: persist the envelope hash (so this post can be RATED or
      // put to a ban poll — previously impossible, because nothing remembered the
      // engine's handle for a message), and track it so a ban that settles later
      // flips its flag (see personasFlags).
      if (personasRecord.kind === 'post') {
        const post = decodePostText(personasRecord.body);
        message.set({
          body: post.text,
          persona: personasRecord.persona,
          personaFlagged: personasRecord.flagged,
          personaEh: personasRecord.eh,
          personaAnonymous: personasRecord.persona == null,
          personaPending: personasRecord.pending === true,
          // The author's own claim, which nothing checks, though nobody else can change it.
          personaBadge: post.badge,
          personaContextName: verifiedContextName(
            personasGroupId,
            personasRecord.eh,
            post.contextName
          ),
        });
        // DIAGNOSTIC. Two questions this answers that nothing else can:
        //
        //   1. did this instance RECEIVE the post at all? Zero decrypt failures and an
        //      empty timeline are consistent with both "never arrived" and "arrived but
        //      did not render", and those have completely different causes.
        //   2. did the CONTEXT NAME travel? The chip renders only when the name is
        //      present, so a missing chip is either a sender that never attached one or
        //      a receiver that failed to decode it. This line distinguishes them.
        //
        // Logged at the point the model is written, so it reflects what the UI will
        // actually read rather than what the wire contained.
        log.info(
          `personas: received post eh=${personasRecord.eh.slice(0, 12)} ` +
          `persona=${personasRecord.persona ?? '(anonymous)'}` +
          `${personasRecord.pending ? ' (held until it applies)' : ''} ` +
          `context=${post.contextName ?? '(none)'} ` +
          `badge=${post.badge ?? '(none)'}`
        );
        trackPersonaPost(personasRecord.eh, message.id);
      }

      // Phase 6: a poll arrives as a record with a display descriptor. It has no
      // plaintext body of its own — the poll bubble renders from personaPoll — so
      // clear the raw carriage body off the model.
      if (personasRecord.kind === 'poll') {
        message.set({
          body: undefined,
          personaEh: personasRecord.eh,
          // A poll now rides the phantom, so its creator is unlinkable. Label it
          // Anonymous rather than letting it fall through to the phantom contact
          // (which Signal would render as "Deleted Account").
          personaAnonymous: true,
          personaPoll: {
            question: personasRecord.descriptor.question,
            options: [...personasRecord.descriptor.options],
            kind: personasRecord.descriptor.kind,
          },
        });
        trackPersonaPost(personasRecord.eh, message.id);
      }

      // A badge request or approval. Rendered as a NOTIFICATION, attributed to the real
      // sender, with the raw carriage body cleared off the model.
      //
      // Deliberately not suppressed. A request needs to be seen by an admin, and burying
      // it in a dialog is what made the flow unexplainable — an admin saw an odd record
      // appear in the chat and had nowhere obvious to act on it. Showing it in the
      // timeline, where the Approve button is attached to the thing being approved, is
      // the whole fix.
      if (
        personasRecord.kind === 'badge-request' ||
        personasRecord.kind === 'badge-approve'
      ) {
        message.set({
          body: undefined,
          // Anonymous, and genuinely so: these ride the phantom (PZB2), so the Signal
          // envelope does not name the sender either. Labelling them anonymous while
          // they still went out attributably would have been a cosmetic lie — the
          // worst kind of privacy UI, since every recipient's client would still know
          // exactly who sent it. `personaAnonymous` also keeps Signal from falling
          // through to the phantom contact and rendering "Deleted Account".
          personaAnonymous: true,
          personaBadgeNotice: {
            kind:
              personasRecord.kind === 'badge-request' ? 'request' : 'approve',
            eh: personasRecord.eh,
            slot: personasRecord.slot,
          },
        });
        log.info(
          `${idLog}: personas ${personasRecord.kind} slot=${personasRecord.slot} ` +
          `eh=${personasRecord.eh.slice(0, 12)}`
        );
      }

      if (storyQuote) {
        await hydrateStoryContext(message.id, storyQuote, {
          shouldSave: true,
        });
      }

      const isSupported = !isUnsupportedMessage(message.attributes);
      if (!isSupported) {
        await eraseMessageContents(message, 'unsupported-message');
      }

      if (isSupported) {
        const attributes = {
          ...conversation.attributes,
        };

        // Drop empty messages after. This needs to happen after the initial
        // message.set call and after GroupV1 processing to make sure all possible
        // properties are set before we determine that a message is empty.
        if (isMessageEmpty(message.attributes)) {
          log.info(`${idLog}: Dropping empty message`);
          confirm();
          return;
        }

        if (isStory(message.attributes)) {
          attributes.hasPostedStory = true;
        } else {
          attributes.active_at = now;
        }

        conversation.set(attributes);

        // Sync group story reply expiration timers with the parent story's
        // expiration timer
        if (isGroupStoryReply && storyQuote) {
          message.set({
            expireTimer: storyQuote.expireTimer,
            expirationStartTimestamp: storyQuote.expirationStartTimestamp,
          });
        }

        if (dataMessage.expireTimer && !isExpirationTimerUpdate(dataMessage)) {
          message.set({ expireTimer: dataMessage.expireTimer });
          if (isStory(message.attributes)) {
            log.info(`${idLog}: Starting story expiration`);
            message.set({
              expirationStartTimestamp: dataMessage.timestamp,
            });
          }
        }

        if (!hasGroupV2Prop && !isStory(message.attributes)) {
          if (isExpirationTimerUpdate(message.attributes)) {
            message.set({
              expirationTimerUpdate: {
                source,
                sourceServiceId,
                expireTimer: initialMessage.expireTimer,
              },
            });

            if (conversation.get('expireTimer') !== dataMessage.expireTimer) {
              log.info('Incoming expirationTimerUpdate changed timer', {
                id: conversation.idForLogging(),
                expireTimer: dataMessage.expireTimer || 'disabled',
                source: idLog,
              });
              conversation.set({
                expireTimer: dataMessage.expireTimer,
              });
            }
          }

          // Note: For incoming expire timer updates (not normal messages that come
          //   along with an expireTimer), the conversation will be updated by this
          //   point and these calls will return early.
          if (dataMessage.expireTimer) {
            void conversation.updateExpirationTimer(dataMessage.expireTimer, {
              source: sourceServiceId || source,
              receivedAt: message.get('received_at'),
              receivedAtMS: message.get('received_at_ms'),
              sentAt: message.get('sent_at'),
              reason: idLog,
              version: initialMessage.expireTimerVersion,
            });
          } else if (
            // We won't turn off timers for these kinds of messages:
            !isGroupUpdate(message.attributes) &&
            !isEndSession(message.attributes)
          ) {
            void conversation.updateExpirationTimer(undefined, {
              source: sourceServiceId || source,
              receivedAt: message.get('received_at'),
              receivedAtMS: message.get('received_at_ms'),
              sentAt: message.get('sent_at'),
              reason: idLog,
              version: initialMessage.expireTimerVersion,
            });
          }
        }

        if (initialMessage.profileKey) {
          const { profileKey } = initialMessage;
          if (
            source === itemStorage.user.getNumber() ||
            sourceServiceId === itemStorage.user.getAci()
          ) {
            conversation.set({ profileSharing: true });
          } else if (isDirectConversation(conversation.attributes)) {
            drop(
              conversation.setProfileKey(profileKey, {
                reason: 'handleDataMessage',
              })
            );
          } else {
            const local = window.ConversationController.lookupOrCreate({
              e164: source,
              serviceId: sourceServiceId,
              reason: 'handleDataMessage:setProfileKey',
            });
            drop(
              local?.setProfileKey(profileKey, {
                reason: 'handleDataMessage',
              })
            );
          }
        }

        if (isTapToView(message.attributes) && type === 'outgoing') {
          await eraseMessageContents(message, 'view-once-sent');
        }

        if (
          type === 'incoming' &&
          isTapToView(message.attributes) &&
          !isValidTapToView(message.attributes)
        ) {
          log.warn(
            `${idLog}: Received tap to view message with invalid data. Erasing contents.`
          );
          message.set({
            isTapToViewInvalid: true,
          });
          await eraseMessageContents(message, 'view-once-invalid');
        }
      }

      const conversationTimestamp = conversation.get('timestamp');
      if (
        !isStory(message.attributes) &&
        !isGroupStoryReply &&
        (!conversationTimestamp ||
          message.get('sent_at') > conversationTimestamp) &&
        messageHasPaymentEvent(message.attributes)
      ) {
        conversation.set({
          lastMessage: getNotificationTextForMessage(message.attributes),
          lastMessageAuthor: getMessageAuthorText(message.attributes),
          lastMessageAuthorAci: getMessageAuthorAci(message.attributes),
          timestamp: message.get('sent_at'),
        });
      }

      // oxlint-disable-next-line no-param-reassign
      message = window.MessageCache.register(message);
      conversation.incrementMessageCount();

      // If we sent a message in a given conversation, unarchive it!
      if (type === 'outgoing') {
        conversation.setArchived(false);
      }

      await DataWriter.updateConversation(conversation.attributes);

      const giftBadge = message.get('giftBadge');
      if (giftBadge && giftBadge.state !== GiftBadgeStates.Failed) {
        const { level } = giftBadge;
        const { updatesUrl } = window.SignalContext.config;
        strictAssert(
          typeof updatesUrl === 'string',
          'getProfile: expected updatesUrl to be a defined string'
        );
        const response = await getCachedSubscriptionConfiguration();
        const boostBadgesByLevel = parseBoostBadgeListFromServer(
          response,
          updatesUrl
        );
        const badge = boostBadgesByLevel[level];
        if (!badge) {
          log.error(
            `${idLog}: gift badge with level ${level} not found on server`
          );
        } else {
          window.reduxActions.badges.updateOrCreate([badge]);
          giftBadge.id = badge.id;
        }
      }

      const result = await modifyTargetMessage(message, conversation, {
        isFirstRun: true,
        skipEdits: false,
      });
      if (result === ModifyTargetMessageResult.Deleted) {
        confirm();
        return;
      }

      log.info(`${idLog}: Batching save`);
      drop(dependencies.saveAndNotify(message, conversation, confirm));
    } catch (error) {
      const errorForLog = Errors.toLogFormat(error);
      log.error(`${idLog}: error:`, errorForLog);
      throw error;
    }
  });
}
