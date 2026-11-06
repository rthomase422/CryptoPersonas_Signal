// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo, Phase 6 — the bubble for a ZK poll.
//
// Deliberately built to look like Signal's own poll bubble (same Axo tokens, same
// layout, same `tw` classes as PollMessageContents) rather than reusing it, because a
// ZK poll differs from a Signal poll in exactly the way that matters:
//
//   * Signal's `PollMessageContents` renders per-option VOTER LISTS and opens a
//     PollVotesModal naming who voted for what. It is typed on
//     `PollWithResolvedVotersType` — resolved voters are load-bearing to it.
//   * A ZK ballot is anonymous by construction. There are no voters to resolve, and
//     synthesising placeholder ones to satisfy that type would put a fiction on screen
//     in the one component whose honesty the whole demo rests on.
//
// So this shows the tally the ENGINE reports and nothing else. It never claims to know
// who voted, because it does not, and neither does anyone else.

import { type JSX } from 'react';

import { tw } from '../../axo/tw.dom.tsx';
import { AxoSymbol } from '../../axo/AxoSymbol.dom.tsx';
import type { DirectionType } from './Message.dom.tsx';
import { UserText } from '../UserText.dom.tsx';

export type PersonaPollForUI = {
  question: string;
  options: ReadonlyArray<string>;
  kind: 'ban' | 'standard';
  // The option index we cast, if any — local bookkeeping only (see personaMyVote).
  myVote?: number;
  // The engine's own status line for this poll, when it publishes one we can match.
  // Shown verbatim: the tally on screen is the engine's, never the UI's arithmetic.
  statusLine?: string;
};

export type PersonaPollMessageProps = {
  poll: PersonaPollForUI;
  direction: DirectionType;
  messageId: string;
  sendPollVote: (params: {
    messageId: string;
    optionIndexes: ReadonlyArray<number>;
  }) => void;
};

export function PersonaPollMessage({
  poll,
  direction,
  messageId,
  sendPollVote,
}: PersonaPollMessageProps): JSX.Element {
  const isIncoming = direction === 'incoming';
  const hasVoted = poll.myVote != null;
  // The replica refuses a ballot after a poll closes, so do not offer one.
  const isClosed = poll.statusLine?.includes('· closed]') ?? false;
  const isLocked = hasVoted || isClosed;

  return (
    <div
      className={tw(
        'text-start wrap-break-word whitespace-pre-wrap',
        'type-body-large',
        isIncoming ? 'text-primary' : 'text-primary-oncolor',
        'w-[275px] max-w-full',
        'mt-1'
      )}
    >
      <div className={tw('mb-1 flex items-start gap-1 font-semibold')}>
        {poll.kind === 'ban' && (
          // A ban poll asks for someone's revocation. Mark it so it cannot be mistaken
          // for an ordinary question.
          <span className={tw('mt-[2px] shrink-0')}>
            <AxoSymbol.InlineGlyph symbol="stop-circle" label="Revocation poll" />
          </span>
        )}
        <span className={tw('min-w-0')}>
          <UserText text={poll.question} />
        </span>
      </div>

      <div
        className={tw(
          'mb-4 type-body-medium font-medium',
          isIncoming ? 'text-secondary' : 'text-secondary-oncolor'
        )}
      >
        {/* Say plainly what is and is not known: the ballot is anonymous, and the
            tally shown is whatever the engine reports. */}
        {poll.statusLine ?? 'Pseudonymous ballot · select one'}
      </div>

      <div className={tw('space-y-3')}>
        {poll.options.map((option, index) => {
          const isMine = poll.myVote === index;
          return (
            <button
              // oxlint-disable-next-line react/no-array-index-key
              key={`persona-poll-option-${index}`}
              type="button"
              // A ZK ballot cannot be recast or withdrawn — the record is already
              // folded into every replica — so once we have voted the options lock.
              disabled={isLocked}
              onClick={() =>
                sendPollVote({ messageId, optionIndexes: [index] })
              }
              className={tw(
                'flex w-full items-start gap-3 rounded-lg px-2 py-1 text-start',
                'outline-none keyboard-mode:focus:axo-focus-ring',
                'transition-colors duration-250',
                isLocked
                  ? 'cursor-default'
                  : isIncoming
                    ? 'hover:bg-fill-secondary'
                    : 'hover:bg-(--axo-color-label-primary-oncolor)/10'
              )}
            >
              <span
                className={tw(
                  'mt-[3px] flex size-5 shrink-0 items-center justify-center rounded-full border-[1.5px]',
                  isMine
                    ? isIncoming
                      ? 'border-(--axo-color-fill-accent) bg-accent text-primary-oncolor'
                      : 'border-(--axo-color-label-primary-oncolor) bg-(--axo-color-label-primary-oncolor) text-(--axo-color-surface-message-outgoing)'
                    : isIncoming
                      ? 'border-(--axo-color-label-placeholder)'
                      : 'border-(--axo-color-label-primary-oncolor)'
                )}
              >
                {isMine && (
                  <AxoSymbol.Icon symbol="check" size={12} label={null} />
                )}
              </span>
              <span className={tw('min-w-0 flex-1 type-body-large')}>
                <UserText text={option} />
              </span>
            </button>
          );
        })}
      </div>

      <div
        className={tw(
          'mt-3 type-body-small',
          isIncoming ? 'text-secondary' : 'text-secondary-oncolor'
        )}
      >
        {/* The one thing worth stating outright: this is not a Signal poll, and the
            result is not the UI's opinion. */}
        Enforced by zero-knowledge proof. Each member votes once, under a
        poll-specific pseudonym not linked to their account.
      </div>
    </div>
  );
}
