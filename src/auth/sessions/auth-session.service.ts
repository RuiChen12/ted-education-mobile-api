import { securityActivityCutoff, parseActivityCursor } from '../security/security-activity.service';
import { enqueueSecurityNotification } from '../../notifications/security-notification.service';
import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from '@prisma/client';
import {
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';

import { PrismaService } from '../../prisma/prisma.service';
import {
  JWT_ACCESS_SECONDS,
  REFRESH_TOKEN_PATTERN,
} from '../jwt/jwt.config';

const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000;
const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;


const DENIED = 'Session expired or revoked. Sign in again.';

@Injectable()
export class AuthSessionService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  private digest(value: string): string {
    const secret = this.config.getOrThrow<string>(
      'REFRESH_TOKEN_SECRET',
    );

    return createHmac('sha256', secret)
      .update('ted:refresh:' + value)
      .digest('hex');
  }

  private newToken(id: string) {
    const token =
      id + '.' + randomBytes(32).toString('base64url');

    return {
      refreshToken: token,
      tokenHash: this.digest(token),
    };
  }

  private tokenId(token: string): string {
    const match = REFRESH_TOKEN_PATTERN.exec(token);

    if (!match) {
      throw new UnauthorizedException(DENIED);
    }

    return match[1];
  }

  private hashEquals(a: string, b: string) {
    if (
      !/^[0-9a-f]{64}$/i.test(a) ||
      !/^[0-9a-f]{64}$/i.test(b)
    ) {
      return false;
    }

    return timingSafeEqual(
      Buffer.from(a, 'hex'),
      Buffer.from(b, 'hex'),
    );
  }

  private async access(
    userId: string,
    sessionId: string,
    version: number,
    refreshToken: string,
  ) {
    const accessToken = await this.jwt.signAsync({
      sub: userId,
      sid: sessionId,
      purpose: 'access',
      sv: version,
    });

    return {
      mfaRequired: false as const,
      accessToken,
      refreshToken,
      tokenType: 'Bearer' as const,
      expiresIn: JWT_ACCESS_SECONDS,
    };
  }

private async lockUser(
    tx: Prisma.TransactionClient,
    userId: string,
  ) {
    await tx.$queryRaw`
      SELECT "id"
      FROM "User"
      WHERE "id" = ${userId}::uuid
      FOR UPDATE
    `;

    const user = await tx.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        isActive: true,
        passwordHash: true,
        emailVerifiedAt: true,
        sessionVersion: true,
      },
    });

    if (
      !user?.isActive ||
      (user.passwordHash && !user.emailVerifiedAt)
    ) {
      throw new UnauthorizedException(DENIED);
    }

    return user;
  }

  private async lockSession(
    tx: Prisma.TransactionClient,
    userId: string,
    sessionId: string,
  ) {
    await tx.$queryRaw`
      SELECT "id"
      FROM "AuthSession"
      WHERE "id" = ${sessionId}::uuid
        AND "userId" = ${userId}::uuid
      FOR UPDATE
    `;

    return tx.authSession.findFirst({
      where: {
        id: sessionId,
        userId,
      },
    });
  }

  private async requireActiveSession(
    tx: Prisma.TransactionClient,
    userId: string,
    sessionId: string,
    version: number,
  ) {
    const session = await this.lockSession(
      tx,
      userId,
      sessionId,
    );

    const now = new Date();

    if (
      !session ||
      session.revokedAt ||
      session.sessionVersion !== version ||
      session.expiresAt <= now ||
      session.absoluteExpiresAt <= now
    ) {
      throw new UnauthorizedException(DENIED);
    }

    return session;
  }


  async issue(userId: string, version: number) {
    return this.prisma.$transaction(
      tx => this.issueInTransaction(tx, userId, version),
    );
  }

  async issueInTransaction(
    tx: Prisma.TransactionClient,
    userId: string,
    version: number,
  ) {
    if (
      !Number.isInteger(version) ||
      version < 0 ||
      version > 2147483647
    ) {
      throw new UnauthorizedException(DENIED);
    }

    const user = await this.lockUser(tx, userId);

    if (user.sessionVersion !== version) {
      throw new UnauthorizedException(DENIED);
    }

    const id = randomUUID();
    const token = this.newToken(id);
    const now = Date.now();

    await tx.authSession.create({
      data: {
        id,
        userId,
        sessionVersion: version,
        tokenHash: token.tokenHash,
        expiresAt: new Date(now + SEVEN_DAYS),
        absoluteExpiresAt: new Date(now + THIRTY_DAYS),
      },
    });

    await tx.securityEvent.create({
      data: {
        userId,
        type: 'SESSION_CREATED',
      },
    });

    return this.access(
      userId,
      id,
      version,
      token.refreshToken,
    );
  }

  private async rejectReplayedToken(
    tx: Prisma.TransactionClient,
    userId: string,
    id: string,
    oldHash: string,
    now: Date,
  ): Promise<void> {
    const used =
      await tx.usedRefreshToken.findUnique({
        where: { tokenHash: oldHash },
        select: {
          sessionId: true,
          usedAt: true,
        },
      });

    if (!used || used.sessionId !== id) {
      return;
    }

    const age = used.usedAt
      ? now.getTime() - used.usedAt.getTime()
      : Number.POSITIVE_INFINITY;

    // All previously consumed tokens are rejected.
    // Preserve the existing duplicate-request grace policy.
    if (age >= 10000 || age < 0) {
      const revoked = await tx.authSession.updateMany({
        where: {
          id,
          userId,
          revokedAt: null,
        },
        data: {
          revokedAt: now,
        },
      });

      if (revoked.count > 0) {
        await tx.securityEvent.create({
          data: {
            userId,
            type: 'REFRESH_TOKEN_REPLAY',
          },
        });
      }
    }
  }

  async refresh(refreshToken: string) {
    const id = this.tokenId(refreshToken);
    const oldHash = this.digest(refreshToken);

    // Initial lookup is used only to identify the owner.
    // Authorization is performed again inside the transaction.
    const owner = await this.prisma.authSession.findUnique({
      where: { id },
      select: { userId: true },
    });

    if (!owner) {
      throw new UnauthorizedException(DENIED);
    }

    const result = await this.prisma.$transaction(
      async tx => {
        const user = await this.lockUser(
          tx,
          owner.userId,
        );

        const session = await this.requireActiveSession(
          tx,
          user.id,
          id,
          user.sessionVersion,
        );

        const now = new Date();

        if (!this.hashEquals(session.tokenHash, oldHash)) {
          await this.rejectReplayedToken(
            tx,
            user.id,
            id,
            oldHash,
            now,
          );

          // Do not throw inside the transaction here.
          // A replay-related revocation must be committed.
          return null;
        }

        const next = this.newToken(id);

        const expiry = new Date(
          Math.min(
            now.getTime() + SEVEN_DAYS,
            session.absoluteExpiresAt.getTime(),
          ),
        );

        const changed = await tx.authSession.updateMany({
          where: {
            id,
            userId: user.id,
            sessionVersion: user.sessionVersion,
            tokenHash: oldHash,
            revokedAt: null,
            expiresAt: { gt: now },
            absoluteExpiresAt: { gt: now },
          },
          data: {
            tokenHash: next.tokenHash,
            expiresAt: expiry,
          },
        });

        if (changed.count !== 1) {
          throw new UnauthorizedException(DENIED);
        }

        await tx.usedRefreshToken.create({
          data: {
            tokenHash: oldHash,
            sessionId: id,
          },
        });

        return this.access(
          user.id,
          id,
          user.sessionVersion,
          next.refreshToken,
        );
      },
    );

    if (!result) {
      throw new UnauthorizedException(DENIED);
    }

    return result;
  }

  async logout(refreshToken: string) {
    const id = this.tokenId(refreshToken);
    const hash = this.digest(refreshToken);

    const owner = await this.prisma.authSession.findUnique({
      where: { id },
      select: { userId: true },
    });

    if (!owner) {
      return { message: 'Signed out.' };
    }

    await this.prisma.$transaction(async tx => {
      await this.lockUser(tx, owner.userId);

      await tx.authSession.updateMany({
        where: {
          id,
          userId: owner.userId,
          tokenHash: hash,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      });
    });

    return { message: 'Signed out.' };
  }

  async logoutCurrent(
    userId: string,
    sessionId: string,
  ) {
    await this.prisma.$transaction(async tx => {
      await this.lockUser(tx, userId);

      const changed = await tx.authSession.updateMany({
        where: {
          id: sessionId,
          userId,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      });

      if (changed.count > 0) {
        await tx.securityEvent.create({
          data: {
            userId,
            type: 'SIGNED_OUT',
          },
        });
      }
    });

    return { message: 'Signed out.' };
  }

  async listSecurityActivity(
    userId: string,
    cursor?: string,
  ) {
    const boundary = parseActivityCursor(cursor);
    const cutoff = securityActivityCutoff();

    const events = await this.prisma.securityEvent.findMany({
      where: {
        userId,
        createdAt: { gte: cutoff },

        ...(boundary ? {
          OR: [
            {
              createdAt: {
                lt: boundary.createdAt,
              },
            },
            {
              createdAt: boundary.createdAt,
              id: { lt: boundary.id },
            },
          ],
        } : {}),
      },

      orderBy: [
        { createdAt: 'desc' },
        { id: 'desc' },
      ],

      take: 51,

      select: {
        id: true,
        type: true,
        createdAt: true,
      },
    });

    const page = events.slice(0, 50);
    const last = page[page.length - 1];
    const hasMore = events.length > 50;

    return {
      events: page,
      hasMore,
      nextCursor:
        hasMore && last
          ? last.createdAt.toISOString() + '~' + last.id
          : null,
    };
  }

  async listSessions(
    userId: string,
    currentSessionId: string,
  ) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        isActive: true,
        sessionVersion: true,
      },
    });

    if (!user?.isActive) {
      throw new UnauthorizedException(DENIED);
    }

    const now = new Date();

    const active = {
      userId,
      sessionVersion: user.sessionVersion,
      revokedAt: null,
      expiresAt: { gt: now },
      absoluteExpiresAt: { gt: now },
    };

    const select = {
      id: true,
      createdAt: true,
      updatedAt: true,
      expiresAt: true,
      absoluteExpiresAt: true,
      devicePlatform: true,
      lastActiveAt: true,
    } as const;

    const [current, others] = await Promise.all([
      this.prisma.authSession.findFirst({
        where: {
          ...active,
          id: currentSessionId,
        },
        select,
      }),

      this.prisma.authSession.findMany({
        where: {
          ...active,
          id: { not: currentSessionId },
        },
        orderBy: [
          { updatedAt: 'desc' },
          { id: 'asc' },
        ],
        take: 101,
        select,
      }),
    ]);

    if (!current) {
      throw new UnauthorizedException(DENIED);
    }

    const sessions = [
      current,
      ...others.slice(0, 100),
    ];

    return {
      sessions: sessions.map(session => ({
        id: session.id,
        current: session.id === currentSessionId,
        createdAt: session.createdAt,
        lastUpdatedAt: session.updatedAt,
        lastActiveAt: session.lastActiveAt,
        devicePlatform: session.devicePlatform,
        expiresAt: new Date(
          Math.min(
            session.expiresAt.getTime(),
            session.absoluteExpiresAt.getTime(),
          ),
        ),
      })),
      hasMore: others.length > 100,
    };
  }

  async revokeSession(
    userId: string,
    currentSessionId: string,
    targetSessionId: string,
  ) {
    if (targetSessionId === currentSessionId) {
      throw new BadRequestException(
        'Use sign out to end your current session.',
      );
    }

    await this.prisma.$transaction(async tx => {
      const user = await this.lockUser(tx, userId);

      await this.requireActiveSession(
        tx,
        userId,
        currentSessionId,
        user.sessionVersion,
      );

      const changed = await tx.authSession.updateMany({
        where: {
          id: targetSessionId,
          userId,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      });

      if (changed.count > 0) {
        await tx.securityEvent.create({
          data: {
            userId,
            type: 'SESSION_REVOKED',
          },
        });
      }
    });

    return {
      message: 'Session revocation processed.',
    };
  }

  async logoutAll(
    userId: string,
    currentSessionId: string,
  ) {
    await this.prisma.$transaction(async tx => {
      const user = await this.lockUser(
        tx,
        userId,
      );

      await this.requireActiveSession(
        tx,
        userId,
        currentSessionId,
        user.sessionVersion,
      );

      const changedUser = await tx.user.updateMany({
        where: {
          id: userId,
          isActive: true,
          sessionVersion: user.sessionVersion,
        },
        data: {
          sessionVersion: { increment: 1 },
        },
      });

      if (changedUser.count !== 1) {
        throw new UnauthorizedException(DENIED);
      }

      await tx.authSession.updateMany({
        where: {
          userId,
          revokedAt: null,
        },
        data: {
          revokedAt: new Date(),
        },
      });

      await tx.securityEvent.create({
        data: {
          userId,
          type: 'ALL_SESSIONS_REVOKED',
        },
      });

      await enqueueSecurityNotification(tx, userId, 'ALL_SESSIONS_REVOKED');
    });

    return { message: 'All sessions revoked.' };
  }
}
