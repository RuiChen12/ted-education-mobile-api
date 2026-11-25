import { enqueueSecurityNotification } from '../../notifications/security-notification.service';
import {
  BadRequestException,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';

import { ConfigService } from '@nestjs/config';
import type { Prisma } from '@prisma/client';

import {
  createHmac,
  randomInt,
  timingSafeEqual,
} from 'node:crypto';

import { hash } from 'bcryptjs';

import { PrismaService } from '../../prisma/prisma.service';

const GENERIC = {
  message: 'If an eligible account exists, a code will be sent.',
};

const INVALID = 'Invalid or expired reset code.';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

const MAX_SENDS = 5;
const MAX_ATTEMPTS = 5;
const CODE_LIFETIME = 10 * MINUTE;

@Injectable()
export class PasswordResetService {
  private readonly logger = new Logger(
    PasswordResetService.name,
  );

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  private digest(
    id: string,
    email: string,
    version: number,
    code: string,
  ): string {
    return createHmac(
      'sha256',
      this.config.getOrThrow<string>(
        'PASSWORD_RESET_SECRET',
      ),
    )
      .update(JSON.stringify([
        'ted:reset:v2',
        id,
        email,
        version,
        code,
      ]))
      .digest('hex');
  }

  private matches(
    actual: string,
    expected: string,
  ): boolean {
    if (
      !/^[a-f0-9]{64}$/i.test(actual) ||
      !/^[a-f0-9]{64}$/i.test(expected)
    ) {
      return false;
    }

    return timingSafeEqual(
      Buffer.from(actual, 'hex'),
      Buffer.from(expected, 'hex'),
    );
  }

  private async lockResetUser(
    tx: Prisma.TransactionClient,
    userId: string,
    email: string,
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
        email: true,
        isActive: true,
        passwordHash: true,
        sessionVersion: true,
        passwordResetSentInWindow: true,
        passwordResetWindowStartedAt: true,
        passwordResetLastSentAt: true,
      },
    });

    if (
      !user?.isActive ||
      !user.passwordHash ||
      user.email !== email
    ) {
      return null;
    }

    return user;
  }

  private async sendEmail(
    key: string,
    from: string,
    email: string,
    subject: string,
    text: string,
  ) {
    const response = await fetch(
      'https://api.resend.com/emails',
      {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + key,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from,
          to: [email],
          subject,
          text,
        }),
        signal: AbortSignal.timeout(10000),
      },
    );

    if (!response.ok) {
      throw new Error('Email delivery failed.');
    }
  }

  async requestCode(emailInput: string) {
    const key = this.config
      .get<string>('RESEND_API_KEY')
      ?.trim();

    const from = this.config
      .get<string>('RESET_EMAIL_FROM')
      ?.trim();

    if (!key || !from) {
      throw new ServiceUnavailableException(
        'Email service is not configured.',
      );
    }

    const email = emailInput.trim().toLowerCase();

    const owner = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (!owner) {
      return GENERIC;
    }

    const code = randomInt(100_000_000)
      .toString()
      .padStart(8, '0');

    const reserved = await this.prisma.$transaction(
      async tx => {
        const user = await this.lockResetUser(
          tx,
          owner.id,
          email,
        );

        if (!user) return null;

        const now = new Date();

        const previous =
          await tx.passwordResetCode.findUnique({
            where: { userId: user.id },
            select: { sentAt: true },
          });

        const lastSent = Math.max(
          user.passwordResetLastSentAt?.getTime() ?? 0,
          previous?.sentAt.getTime() ?? 0,
        );

        if (
          lastSent > 0 &&
          now.getTime() - lastSent < MINUTE
        ) {
          return null;
        }

        const started =
          user.passwordResetWindowStartedAt;

        const sameWindow = Boolean(
          started &&
          now.getTime() - started.getTime() < HOUR,
        );

        const sentInWindow = sameWindow
          ? user.passwordResetSentInWindow
          : 0;

        if (sentInWindow >= MAX_SENDS) {
          return null;
        }

        const codeHash = this.digest(
          user.id,
          user.email,
          user.sessionVersion,
          code,
        );

        const expiresAt = new Date(
          now.getTime() + CODE_LIFETIME,
        );

        await tx.user.update({
          where: { id: user.id },
          data: {
            passwordResetLastSentAt: now,
            passwordResetSentInWindow: sentInWindow + 1,
            passwordResetWindowStartedAt:
              sameWindow && started
                ? started
                : now,
          },
        });

        await tx.passwordResetCode.upsert({
          where: { userId: user.id },
          create: {
            userId: user.id,
            codeHash,
            attempts: 0,
            sentAt: now,
            expiresAt,
          },
          update: {
            codeHash,
            attempts: 0,
            sentAt: now,
            expiresAt,
          },
        });

        return {
          userId: user.id,
          email: user.email,
          codeHash,
          sentAt: now,
        };
      },
    );

    if (!reserved) {
      return GENERIC;
    }

    try {
      await this.sendEmail(
        key,
        from,
        reserved.email,
        'TED Education: Password reset code',
        'Your reset code is ' + code +
          '. It expires in 10 minutes. ' +
          'Do not share this code with anyone. ' +
          'If this was not you, ignore this email.',
      );
    } catch {
      this.logger.warn(
        'Password reset email could not be delivered.',
      );

      try {
        await this.prisma.$transaction(async tx => {
          const user = await this.lockResetUser(
            tx,
            reserved.userId,
            reserved.email,
          );

          if (!user) return;

          // Invalidate only this failed delivery.
          // Do not reset account-level sending quotas.
          await tx.passwordResetCode.updateMany({
            where: {
              userId: reserved.userId,
              codeHash: reserved.codeHash,
              sentAt: reserved.sentAt,
            },
            data: {
              expiresAt: new Date(),
              attempts: MAX_ATTEMPTS,
            },
          });
        });
      } catch {
        this.logger.warn(
          'Failed reset delivery invalidation could not be confirmed.',
        );
      }
    }

    return GENERIC;
  }

  async resetPassword(
    emailInput: string,
    code: string,
    newPassword: string,
  ) {
    if (
      typeof newPassword !== 'string' ||
      Array.from(newPassword).length < 12 ||
      Buffer.byteLength(newPassword, 'utf8') > 72
    ) {
      throw new BadRequestException(
        'Password must contain at least 12 characters and at most 72 UTF-8 bytes.',
      );
    }

    if (
      typeof code !== 'string' ||
      code.length !== 8 ||
      !/^[0-9]{8}$/.test(code)
    ) {
      throw new BadRequestException(INVALID);
    }

    const email = emailInput.trim().toLowerCase();

    const owner = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (!owner) {
      throw new BadRequestException(INVALID);
    }

    // First transaction: verify the code before
    // performing an expensive bcrypt operation.
    const snapshot = await this.prisma.$transaction(
      async tx => {
        const user = await this.lockResetUser(
          tx,
          owner.id,
          email,
        );

        if (!user) return null;

        const record =
          await tx.passwordResetCode.findUnique({
            where: { userId: user.id },
          });

        if (
          !record ||
          record.expiresAt <= new Date() ||
          record.attempts >= MAX_ATTEMPTS
        ) {
          return null;
        }

        const expected = this.digest(
          user.id,
          user.email,
          user.sessionVersion,
          code,
        );

        if (!this.matches(record.codeHash, expected)) {
          await tx.passwordResetCode.updateMany({
            where: {
              userId: user.id,
              codeHash: record.codeHash,
              sentAt: record.sentAt,
              attempts: { lt: MAX_ATTEMPTS },
            },
            data: {
              attempts: { increment: 1 },
            },
          });

          // Failed attempts must commit.
          return null;
        }

        return {
          userId: user.id,
          sessionVersion: user.sessionVersion,
          passwordHash: user.passwordHash,
          codeHash: record.codeHash,
          sentAt: record.sentAt,
        };
      },
    );

    if (!snapshot) {
      throw new BadRequestException(INVALID);
    }

    // Keep expensive hashing outside database locks.
    const passwordHash = await hash(newPassword, 12);

    // Second transaction: revalidate the entire snapshot
    // and atomically perform the password reset.
    await this.prisma.$transaction(async tx => {
      const user = await this.lockResetUser(
        tx,
        snapshot.userId,
        email,
      );

      if (
        !user ||
        user.sessionVersion !== snapshot.sessionVersion ||
        user.passwordHash !== snapshot.passwordHash
      ) {
        throw new BadRequestException(INVALID);
      }

      const now = new Date();

      const consumed =
        await tx.passwordResetCode.deleteMany({
          where: {
            userId: user.id,
            codeHash: snapshot.codeHash,
            sentAt: snapshot.sentAt,
            attempts: { lt: MAX_ATTEMPTS },
            expiresAt: { gt: now },
          },
        });

      if (consumed.count !== 1) {
        throw new BadRequestException(INVALID);
      }

      const changed = await tx.user.updateMany({
        where: {
          id: user.id,
          email,
          isActive: true,
          sessionVersion: snapshot.sessionVersion,
          passwordHash: snapshot.passwordHash,
        },
        data: {
          passwordHash,
          sessionVersion: { increment: 1 },
        },
      });

      if (changed.count !== 1) {
        throw new BadRequestException(INVALID);
      }

      await tx.authSession.updateMany({
        where: {
          userId: user.id,
          revokedAt: null,
        },
        data: {
          revokedAt: now,
        },
      });

      await tx.emailChangeRequest.updateMany({
          where: { userId: user.id },
          data: { attempts: 5 },
        });

      // Preserve existing email verification quota.
      await tx.emailVerificationCode.updateMany({
        where: { userId: user.id },
        data: {
          attempts: 5,
        },
      });

      // Preserve Google challenge quota while
      // invalidating pending sensitive operations.
      await tx.googleActionChallenge.updateMany({
        where: {
          userId: user.id,
          consumedAt: null,
        },
        data: {
          consumedAt: now,
        },
      });

      await tx.securityEvent.create({
        data: {
          userId: user.id,
          type: 'PASSWORD_RESET',
        },
      });

      await enqueueSecurityNotification(tx, user.id, 'PASSWORD_RESET');

      // Never remove MFA or automatically verify email.
    });


    return {
      message: 'Password changed. Sign in again.',
    };
  }
}
