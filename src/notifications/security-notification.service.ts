import { localizedSecurityText, normalizeNotificationLanguage } from './security-notification.locales';
import {
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from '@nestjs/common';

import { ConfigService } from '@nestjs/config';
import type { Prisma } from '@prisma/client';
import { randomUUID } from 'node:crypto';

import { PrismaService } from '../prisma/prisma.service';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

const MAX_ATTEMPTS = 8;
const MAX_AGE = 23 * HOUR;
const RETENTION = 7 * 24 * HOUR;
const LEASE = 60_000;
const POLL_INTERVAL = 30_000;
const BATCH_SIZE = 10;

const TEMPLATES = {
  PASSWORD_CHANGED: {
    subject: 'Your password was changed',
    action: 'Your TED Education account password was changed.',
  },

  PASSWORD_RESET: {
    subject: 'Your password was reset',
    action: 'Your TED Education account password was reset.',
  },

  MFA_ENABLED: {
    subject: 'Two-factor authentication enabled',
    action: 'Two-factor authentication was enabled on your account.',
  },

  MFA_DISABLED: {
    subject: 'Two-factor authentication disabled',
    action: 'Two-factor authentication was disabled on your account.',
  },

  RECOVERY_CODES_REGENERATED: {
    subject: 'Recovery codes replaced',
    action: 'New recovery codes were generated for your account. Previous recovery codes are no longer valid.',
  },

  GOOGLE_LINKED: {
    subject: 'Google account connected',
    action: 'A Google sign-in method was connected to your account.',
  },

  GOOGLE_UNLINKED: {
    subject: 'Google account disconnected',
    action: 'A Google sign-in method was disconnected from your account.',
  },

  EMAIL_CHANGED: {
    subject: 'Your account email was changed',
    action: 'The email address associated with your TED Education account was changed.',
  },

  ALL_SESSIONS_REVOKED: {
    subject: 'All devices signed out',
    action: 'All previous sign-in sessions for your account were revoked.',
  },
} as const;

type NotificationKind = keyof typeof TEMPLATES;

function isNotificationKind(
  value: string,
): value is NotificationKind {
  return Object.prototype.hasOwnProperty.call(
    TEMPLATES,
    value,
  );
}

/**
 * Create an outbox record in the same transaction
 * as the account security operation.
 *
 * Never store passwords, tokens, recovery codes
 * or authenticator secrets in notification jobs.
 */
export async function enqueueSecurityNotification(
  tx: Prisma.TransactionClient,
  userId: string,
  kind: NotificationKind,
  verifiedRecipient?: string,
): Promise<void> {
  const user = await tx.user.findUnique({
    where: { id: userId },
    select: {
      email: true,
      emailVerifiedAt: true,
      preferredLanguage: true,
    },
  });

  if (!user) {
    throw new Error(
      'Notification account no longer exists.',
    );
  }

  // For an email change, the caller supplies
  // the previously verified email address.
  //
  // Otherwise only use a verified account email.
  const recipient = verifiedRecipient ??
    (user.emailVerifiedAt ? user.email : null);

  if (!recipient) {
    return;
  }

  await tx.securityNotification.create({
    data: {
      userId,
      recipient,
      kind,
      language: normalizeNotificationLanguage(user.preferredLanguage),
    },
  });
}

@Injectable()
export class SecurityNotificationService
  implements OnModuleInit, OnModuleDestroy {

  private readonly logger = new Logger(
    SecurityNotificationService.name,
  );

  private timer: ReturnType<typeof setInterval> | null = null;

  private running: Promise<void> | null = null;

  private stopping = false;
  private configurationWarning = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  onModuleInit(): void {
    this.stopping = false;

    this.timer = setInterval(
      () => this.tick(),
      POLL_INTERVAL,
    );

    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    this.stopping = true;

    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    if (this.running) {
      await this.running;
    }
  }

  private tick(): void {
    if (this.stopping || this.running) {
      return;
    }

    this.running = this.processBatch()
      .catch(() => {
        this.logger.warn(
          'Security notification worker could not complete a batch.',
        );
      })
      .finally(() => {
        this.running = null;
      });
  }

  private async processBatch(): Promise<void> {
    const now = new Date();

    // Expire abandoned or exhausted jobs.
    // Preserve active leases until they expire.

    const expired =
      await this.prisma.securityNotification.updateMany({
        where: {
          deliveredAt: null,
          failedAt: null,
          notBefore: { lte: now },
          OR: [
            {
              createdAt: {
                lte: new Date(
                  now.getTime() - MAX_AGE,
                ),
              },
            },
            {
              attempts: {
                gte: MAX_ATTEMPTS,
              },
            },
          ],
        },
        data: {
          failedAt: now,
          claimId: null,
          recipient: '',
        },
      });

    if (expired.count > 0) {
      this.logger.warn(
        'Security notifications expired or exhausted retries: ' +
          expired.count,
      );
    }

    // Retain terminal metadata for a limited period.

    const retentionCutoff = new Date(
      now.getTime() - RETENTION,
    );

    await this.prisma.securityNotification.deleteMany({
      where: {
        OR: [
          {
            deliveredAt: {
              lte: retentionCutoff,
            },
          },
          {
            failedAt: {
              lte: retentionCutoff,
            },
          },
        ],
      },
    });

    const key = this.config
      .get<string>('RESEND_API_KEY')
      ?.trim();

    const from = this.config
      .get<string>('RESET_EMAIL_FROM')
      ?.trim();

    if (!key || !from) {
      if (!this.configurationWarning) {
        this.logger.warn(
          'Security notification email service is not configured.',
        );

        this.configurationWarning = true;
      }

      return;
    }

    this.configurationWarning = false;

    const jobs =
      await this.prisma.securityNotification.findMany({
        where: {
          deliveredAt: null,
          failedAt: null,
          notBefore: { lte: now },
          attempts: { lt: MAX_ATTEMPTS },
          createdAt: {
            gt: new Date(
              now.getTime() - MAX_AGE,
            ),
          },
        },
        orderBy: [
          { notBefore: 'asc' },
          { createdAt: 'asc' },
        ],
        take: BATCH_SIZE,
      });

    for (const job of jobs) {
      if (this.stopping) {
        return;
      }

      await this.deliver(
        job,
        key,
        from,
      );
    }
  }

  private async deliver(
    job: {
      id: string;
      recipient: string;
      kind: string;
      language: string;
      attempts: number;
      createdAt: Date;
    },
    key: string,
    from: string,
  ): Promise<void> {
    const now = new Date();
    const claimId = randomUUID();

    // Compare-and-set claim: only one worker may
    // acquire the current delivery attempt.

    const claimed =
      await this.prisma.securityNotification.updateMany({
        where: {
          id: job.id,
          attempts: job.attempts,
          deliveredAt: null,
          failedAt: null,
          notBefore: { lte: now },
          createdAt: {
            gt: new Date(
              now.getTime() - MAX_AGE,
            ),
          },
        },
        data: {
          claimId,
          attempts: { increment: 1 },
          notBefore: new Date(
            now.getTime() + LEASE,
          ),
        },
      });

    if (claimed.count !== 1) {
      return;
    }

    const attempt = job.attempts + 1;

    let delivered = false;
    let retryable = true;

    if (
      !isNotificationKind(job.kind) ||
      !job.recipient
    ) {
      retryable = false;
    } else {
      const template = TEMPLATES[job.kind];

      const t = (key: string) =>
        localizedSecurityText(job.language, key);

      try {
        const response = await fetch(
          'https://api.resend.com/emails',
          {
            method: 'POST',

            headers: {
              Authorization: 'Bearer ' + key,
              'Content-Type': 'application/json',

              // Use the same provider idempotency key
              // for every retry of this notification.
              'Idempotency-Key':
                'ted-security-' + job.id,
            },

            body: JSON.stringify({
              from,
              to: [job.recipient],
              subject:
                'TED Education: ' + t(template.subject),

              text: [
                t(template.action),
                '',
                t('Time (UTC):') + ' ' +
                  job.createdAt.toISOString(),
                '',
                t('If you performed this action, no further action is required.'),
                '',
                t('If you did not perform this action, open the TED Education app directly, review your account security, and contact TED support.'),
                '',
                t('Never share passwords or verification codes.'),
              ].join('\n'),
            }),

            signal: AbortSignal.timeout(5000),
          },
        );

        delivered = response.ok;

        retryable =
          response.status >= 500 ||
          response.status === 408 ||
          response.status === 409 ||
          response.status === 429;

        // Do not log provider response bodies.
        if (response.body) {
          await response.body.cancel().catch(() => {});
        }

      } catch {
        retryable = true;
      }
    }

    const finishedAt = new Date();

    const ownership = {
      id: job.id,
      claimId,
      deliveredAt: null,
      failedAt: null,
    };

    if (delivered) {
      await this.prisma.securityNotification.updateMany({
        where: ownership,
        data: {
          deliveredAt: finishedAt,
          claimId: null,
          recipient: '',
        },
      });

      return;
    }

    const delay = Math.min(
      HOUR,
      MINUTE * 2 ** Math.max(0, attempt - 1),
    );

    const terminal =
      !retryable ||
      attempt >= MAX_ATTEMPTS ||
      finishedAt.getTime() + delay >=
        job.createdAt.getTime() + MAX_AGE;

    if (terminal) {
      await this.prisma.securityNotification.updateMany({
        where: ownership,
        data: {
          failedAt: finishedAt,
          claimId: null,
          recipient: '',
        },
      });

      this.logger.warn(
        'A security notification reached terminal failure.',
      );

      return;
    }

    await this.prisma.securityNotification.updateMany({
      where: ownership,
      data: {
        claimId: null,
        notBefore: new Date(
          finishedAt.getTime() + delay,
        ),
      },
    });
  }
}
