import {
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from '@nestjs/common';

import { PrismaService } from '../../prisma/prisma.service';

const DAY = 24 * 60 * 60 * 1000;
const SESSION_RETENTION = 7 * DAY;
const CLEANUP_INTERVAL = 10 * 60 * 1000;

@Injectable()
export class SecurityLifecycleService
  implements OnModuleInit, OnModuleDestroy {

  private readonly logger = new Logger(
    SecurityLifecycleService.name,
  );

  private timer: ReturnType<typeof setInterval> | null = null;
  private running: Promise<void> | null = null;

  constructor(
    private readonly prisma: PrismaService,
  ) {}

  onModuleInit(): void {
    this.timer = setInterval(() => {
      this.tick();
    }, CLEANUP_INTERVAL);

    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    await this.running;
  }

  private tick(): void {
    if (this.running) return;

    this.running = this.cleanup()
      .catch(() => {
        this.logger.warn(
          'Security lifecycle cleanup failed.',
        );
      })
      .finally(() => {
        this.running = null;
      });
  }

  private async cleanup(): Promise<void> {
    const cutoff = new Date(
      Date.now() - SESSION_RETENTION,
    );

    // Delete only sessions that have already been
    // expired or revoked for at least seven days.
    //
    // UsedRefreshToken rows are removed by their
    // existing ON DELETE CASCADE relation.
    //
    // Never prune tokens belonging to active sessions.

    await this.prisma.$executeRaw`
      DELETE FROM "AuthSession"
      WHERE "id" IN (
        SELECT "id"
        FROM "AuthSession"
        WHERE
          "expiresAt" <= ${cutoff}
          OR "absoluteExpiresAt" <= ${cutoff}
          OR "revokedAt" <= ${cutoff}
        ORDER BY "absoluteExpiresAt", "id"
        LIMIT 500
        FOR UPDATE SKIP LOCKED
      )
    `;

    const now = new Date();

    await this.prisma.$executeRaw`
      DELETE FROM "MfaLoginChallenge"
      WHERE "userId" IN (
        SELECT "userId"
        FROM "MfaLoginChallenge"
        WHERE "expiresAt" <= ${now}
        ORDER BY "expiresAt"
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
      )
    `;

    // Remove expired throttling records in bounded batches.

    await this.prisma.$executeRaw`
      DELETE FROM "RateLimitBucket"
      WHERE "key" IN (
        SELECT "key"
        FROM "RateLimitBucket"
        WHERE "expiresAt" <=
          timezone('UTC', statement_timestamp())
        ORDER BY "expiresAt"
        LIMIT 2000
        FOR UPDATE SKIP LOCKED
      )
    `;
  }
}
