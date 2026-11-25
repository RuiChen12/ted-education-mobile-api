
import {
  BadRequestException,
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from '@nestjs/common';

import type { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { UUID_V4_PATTERN } from '../jwt/jwt.config';

const FIVE_MINUTES = 300000;
const RETENTION = 90 * 24 * 60 * 60 * 1000;

type LimitedEvent =
  | 'PASSWORD_LOGIN_FAILED'
  | 'MFA_VERIFICATION_FAILED';

export function securityActivityCutoff(): Date {
  return new Date(Date.now() - RETENTION);
}

export async function lockSecurityActivityUser(
  tx: Prisma.TransactionClient,
  userId: string,
): Promise<void> {
  await tx.$queryRaw`
    SELECT "id" FROM "User"
    WHERE "id" = ${userId}::uuid
    FOR UPDATE
  `;
}

// Caller must hold the User row lock.
// Rate limiting is serialized across server instances.

export async function recordLimitedSecurityEvent(
  tx: Prisma.TransactionClient,
  userId: string,
  type: LimitedEvent,
  now = new Date(),
): Promise<void> {
  const recent = await tx.securityEvent.findFirst({
    where: {
      userId,
      type,
      createdAt: {
        gte: new Date(now.getTime() - FIVE_MINUTES),
      },
    },
    select: { id: true },
  });

  if (recent) return;

  await tx.securityEvent.create({
    data: {
      userId,
      type,
      createdAt: now,
    },
  });
}

export function parseActivityCursor(cursor?: string) {
  if (cursor === undefined) return null;

  if (
    typeof cursor !== 'string' ||
    cursor.length > 80
  ) {
    throw new BadRequestException('Invalid activity cursor.');
  }

  const parts = cursor.split('~');

  if (
    parts.length !== 2 ||
    !UUID_V4_PATTERN.test(parts[1])
  ) {
    throw new BadRequestException('Invalid activity cursor.');
  }

  const createdAt = new Date(parts[0]);

  if (
    !Number.isFinite(createdAt.getTime()) ||
    createdAt.toISOString() !== parts[0]
  ) {
    throw new BadRequestException('Invalid activity cursor.');
  }

  return {
    id: parts[1].toLowerCase(),
    createdAt,
  };
}

@Injectable()
export class SecurityActivityService
  implements OnModuleInit, OnModuleDestroy {

  private readonly logger = new Logger(
    SecurityActivityService.name,
  );

  private timer: ReturnType<typeof setInterval> | null = null;
  private running: Promise<void> | null = null;

  constructor(
    private readonly prisma: PrismaService,
  ) {}

  onModuleInit(): void {
    this.timer = setInterval(() => {
      if (this.running) return;

      this.running = this.cleanup()
        .catch(() => {
          this.logger.warn(
            'Security activity retention cleanup failed.',
          );
        })
        .finally(() => {
          this.running = null;
        });
    }, 600000);

    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    await this.running;
  }

  private async cleanup(): Promise<void> {
    const cutoff = securityActivityCutoff();

    // Bounded cleanup with row locking.
    // Multiple instances can safely clean separate batches.
    await this.prisma.$executeRaw`
      DELETE FROM "SecurityEvent"
      WHERE "id" IN (
        SELECT "id"
        FROM "SecurityEvent"
        WHERE "createdAt" < ${cutoff}
        ORDER BY "createdAt" ASC
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
      )
    `;
  }
}
