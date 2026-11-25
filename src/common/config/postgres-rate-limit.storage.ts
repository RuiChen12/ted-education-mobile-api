import { ServiceUnavailableException } from '@nestjs/common';
import { createHash } from 'node:crypto';

import type { ThrottlerStorage } from '@nestjs/throttler';
import { PrismaService } from '../../prisma/prisma.service';

type BucketResult = {
  hits: number;
  blocked: boolean;
  remaining: number;
};

export class PostgresRateLimitStorage
  implements ThrottlerStorage {

  constructor(
    private readonly prisma: PrismaService,
  ) {}

  async increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    throttlerName: string,
  ) {
    const duration = blockDuration > 0
      ? blockDuration
      : ttl;

    if (
      !Number.isSafeInteger(ttl) ||
      ttl < 1 ||
      ttl > 604800000 ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 1000000 ||
      !Number.isSafeInteger(duration) ||
      duration < 1 ||
      duration > 604800000
    ) {
      throw new ServiceUnavailableException(
        'Request limit configuration is unavailable.',
      );
    }

    const digest = createHash('sha256')
      .update(JSON.stringify([
        throttlerName,
        key,
      ]))
      .digest('hex');

    try {
      // PostgreSQL serializes conflicting updates
      // to the same rate-limit bucket.
      //
      // Use the database clock, rather than relying
      // on synchronized API-instance clocks.

      const rows =
        await this.prisma.$queryRaw<BucketResult[]>`
          INSERT INTO "RateLimitBucket" (
            "key",
            "hits",
            "blocked",
            "expiresAt"
          )
          VALUES (
            ${digest},
            1,
            FALSE,
            timezone('UTC', statement_timestamp())
              + (${ttl}::double precision * interval '1 millisecond')
          )
          ON CONFLICT ("key")
          DO UPDATE SET
            "hits" = CASE
              WHEN "RateLimitBucket"."expiresAt"
                <= timezone('UTC', statement_timestamp())
                THEN 1
              WHEN "RateLimitBucket"."blocked"
                THEN "RateLimitBucket"."hits"
              ELSE LEAST(
                "RateLimitBucket"."hits",
                ${limit}::integer
              ) + 1
            END,

            "blocked" = CASE
              WHEN "RateLimitBucket"."expiresAt"
                <= timezone('UTC', statement_timestamp())
                THEN FALSE
              WHEN "RateLimitBucket"."blocked"
                THEN TRUE
              ELSE "RateLimitBucket"."hits"
                >= ${limit}::integer
            END,

            "expiresAt" = CASE
              WHEN "RateLimitBucket"."expiresAt"
                <= timezone('UTC', statement_timestamp())
                THEN timezone('UTC', statement_timestamp())
                  + (${ttl}::double precision * interval '1 millisecond')
              WHEN "RateLimitBucket"."blocked"
                THEN "RateLimitBucket"."expiresAt"
              WHEN "RateLimitBucket"."hits"
                >= ${limit}::integer
                THEN timezone('UTC', statement_timestamp())
                  + (${duration}::double precision * interval '1 millisecond')
              ELSE "RateLimitBucket"."expiresAt"
            END

          RETURNING
            "hits",
            "blocked",
            EXTRACT(EPOCH FROM (
              "expiresAt" -
              timezone('UTC', clock_timestamp())
            ))::double precision AS "remaining"
        `;

      const bucket = rows[0];

      if (!bucket) {
        throw new Error(
          'Missing rate-limit bucket.',
        );
      }

      const remaining = Math.max(
        1,
        Math.ceil(bucket.remaining),
      );

      return {
        totalHits: bucket.hits,
        timeToExpire: remaining,
        isBlocked: bucket.blocked,
        timeToBlockExpire: bucket.blocked
          ? remaining
          : 0,
      };

    } catch {
      // Fail closed rather than silently disabling
      // request limits during database failures.
      throw new ServiceUnavailableException(
        'Request limiting is temporarily unavailable.',
      );
    }
  }
}
