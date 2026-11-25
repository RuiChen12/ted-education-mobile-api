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

import { PrismaService } from '../../prisma/prisma.service';

const GENERIC = {
  message: 'If verification is needed, a code will be sent.',
};

const INVALID = 'Invalid or expired verification code.';

const MINUTE = 60_000;
const CODE_LIFETIME = 10 * MINUTE;
const RESEND_DELAY = MINUTE;
const DAILY_WINDOW = 24 * 60 * MINUTE;
const MAX_SENDS = 5;
const MAX_ATTEMPTS = 5;

@Injectable()
export class EmailVerificationService {
  private readonly logger = new Logger(
    EmailVerificationService.name,
  );

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  private digest(
    userId: string,
    email: string,
    version: number,
    sentAt: Date,
    code: string,
  ): string {
    const secret = this.config.getOrThrow<string>(
      'EMAIL_VERIFICATION_SECRET',
    );

    return createHmac('sha256', secret)
      .update(JSON.stringify([
        'ted:verify-email:v2',
        userId,
        email,
        version,
        sentAt.toISOString(),
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

  private async lockVerificationUser(
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
        emailVerifiedAt: true,
        sessionVersion: true,
      },
    });

    if (
      !user?.isActive ||
      !user.passwordHash ||
      user.emailVerifiedAt ||
      user.email !== email
    ) {
      return null;
    }

    return user;
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
        const user = await this.lockVerificationUser(
          tx,
          owner.id,
          email,
        );

        if (!user) return null;

        const now = new Date();

        const previous =
          await tx.emailVerificationCode.findUnique({
            where: { userId: user.id },
          });

        if (
          previous &&
          now.getTime() - previous.sentAt.getTime() <
            RESEND_DELAY
        ) {
          return null;
        }

        const sameWindow = Boolean(
          previous &&
          now.getTime() -
            previous.windowStartedAt.getTime() <
            DAILY_WINDOW,
        );

        const sentInWindow =
          previous && sameWindow
            ? previous.sentInWindow
            : 0;

        if (sentInWindow >= MAX_SENDS) {
          return null;
        }

        const codeHash = this.digest(
          user.id,
          user.email,
          user.sessionVersion,
          now,
          code,
        );

        const data = {
          codeHash,
          attempts: 0,
          sentAt: now,
          expiresAt: new Date(
            now.getTime() + CODE_LIFETIME,
          ),
          sentInWindow: sentInWindow + 1,
          windowStartedAt:
            previous && sameWindow
              ? previous.windowStartedAt
              : now,
        };

        await tx.emailVerificationCode.upsert({
          where: { userId: user.id },
          create: {
            userId: user.id,
            ...data,
          },
          update: data,
        });

        return {
          email: user.email,
        };
      },
    );

    if (!reserved) {
      return GENERIC;
    }

    // Do not hold database locks during email delivery.
    try {
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
            to: [reserved.email],
            subject: 'TED Education: Verify your email',
            text:
              'Your verification code is ' + code +
              '. It expires in 10 minutes. ' +
              'Do not share this code with anyone. ' +
              'If you did not register, ignore this email.',
          }),
          signal: AbortSignal.timeout(10000),
        },
      );

      if (!response.ok) {
        throw new Error('Email delivery failed.');
      }
    } catch {
      this.logger.warn(
        'Verification email delivery could not be confirmed.',
      );

      // Preserve the code and quota because a timeout
      // does not prove that delivery failed.
    }

    return GENERIC;
  }

  async confirmCode(
    emailInput: string,
    code: string,
  ) {
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

    const verified = await this.prisma.$transaction(
      async tx => {
        const user = await this.lockVerificationUser(
          tx,
          owner.id,
          email,
        );

        if (!user) return false;

        const record =
          await tx.emailVerificationCode.findUnique({
            where: { userId: user.id },
          });

        const now = new Date();

        if (
          !record ||
          record.expiresAt <= now ||
          record.attempts >= MAX_ATTEMPTS
        ) {
          return false;
        }

        const expected = this.digest(
          user.id,
          user.email,
          user.sessionVersion,
          record.sentAt,
          code,
        );

        if (!this.matches(record.codeHash, expected)) {
          await tx.emailVerificationCode.updateMany({
            where: {
              userId: user.id,
              codeHash: record.codeHash,
              sentAt: record.sentAt,
              attempts: { lt: MAX_ATTEMPTS },
              expiresAt: { gt: now },
            },
            data: {
              attempts: { increment: 1 },
            },
          });

          // Commit failed attempts before returning an error.
          return false;
        }

        // Consume the verification code without removing
        // the existing sending-quota history.
        const consumed =
          await tx.emailVerificationCode.updateMany({
            where: {
              userId: user.id,
              codeHash: record.codeHash,
              sentAt: record.sentAt,
              attempts: { lt: MAX_ATTEMPTS },
              expiresAt: { gt: now },
            },
            data: {
              expiresAt: now,
              attempts: MAX_ATTEMPTS,
            },
          });

        if (consumed.count !== 1) {
          throw new BadRequestException(INVALID);
        }

        const updated = await tx.user.updateMany({
          where: {
            id: user.id,
            email: user.email,
            passwordHash: user.passwordHash,
            sessionVersion: user.sessionVersion,
            isActive: true,
            emailVerifiedAt: null,
          },
          data: {
            emailVerifiedAt: now,
          },
        });

        if (updated.count !== 1) {
          throw new BadRequestException(INVALID);
        }

        return true;
      },
    );

    if (!verified) {
      throw new BadRequestException(INVALID);
    }

    return {
      message: 'Email verified. You can now sign in.',
    };
  }
}
