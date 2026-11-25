import { enqueueSecurityNotification } from '../../notifications/security-notification.service';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';

import { ConfigService } from '@nestjs/config';
import { Prisma } from '@prisma/client';
import { compare } from 'bcryptjs';

import {
  createHmac,
  randomInt,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';

import { PrismaService } from '../../prisma/prisma.service';
import { MfaService } from '../mfa/mfa.service';

const MINUTE = 60000;
const HOUR = 60 * MINUTE;
const INVALID = 'Invalid or expired email change request.';

@Injectable()
export class EmailChangeService {
  private readonly logger =
    new Logger(EmailChangeService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly mfa: MfaService,
  ) {}

  private digest(
    userId: string,
    requestId: string,
    side: 'old' | 'new',
    code: string,
  ) {
    return createHmac(
      'sha256',
      this.config.getOrThrow<string>(
        'PASSWORD_RESET_SECRET',
      ),
    )
      .update(
        'ted:email-change:v1:' +
        userId + ':' +
        requestId + ':' +
        side + ':' +
        code,
      )
      .digest('hex');
  }

  private matches(a: string, b: string) {
    if (
      !/^[a-f0-9]{64}$/i.test(a) ||
      !/^[a-f0-9]{64}$/i.test(b)
    ) {
      return false;
    }

    return timingSafeEqual(
      Buffer.from(a, 'hex'),
      Buffer.from(b, 'hex'),
    );
  }

  private async send(
    email: string,
    subject: string,
    text: string,
  ) {
    const key =
      this.config.get<string>('RESEND_API_KEY')?.trim();

    const from =
      this.config.get<string>('RESET_EMAIL_FROM')?.trim();

    if (!key || !from) {
      throw new ServiceUnavailableException(
        'Email service is unavailable.',
      );
    }

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
        signal: AbortSignal.timeout(5000),
      },
    );

    if (!response.ok) {
      throw new ServiceUnavailableException(
        'Email delivery could not be confirmed.',
      );
    }
  }

  private async lockAccount(
    tx: Prisma.TransactionClient,
    userId: string,
    sessionId: string,
  ) {
    await tx.$queryRaw`
      SELECT "id"
      FROM "User"
      WHERE "id" = ${userId}::uuid
      FOR UPDATE
    `;

    await tx.$queryRaw`
      SELECT "id"
      FROM "AuthSession"
      WHERE "id" = ${sessionId}::uuid
        AND "userId" = ${userId}::uuid
      FOR UPDATE
    `;

    const user = await tx.user.findUnique({
      where: { id: userId },
      select: {
        email: true,
        passwordHash: true,
        sessionVersion: true,
        emailVerifiedAt: true,
        isActive: true,
        _count: {
          select: {
            socialAccounts: true,
          },
        },
      },
    });

    if (
      !user?.isActive ||
      !user.emailVerifiedAt
    ) {
      throw new UnauthorizedException(
        'Sign in again.',
      );
    }

    if (
      !user.passwordHash ||
      user._count.socialAccounts !== 0
    ) {
      throw new BadRequestException(
        'Email changes for linked sign-in accounts are not supported yet.',
      );
    }

    const now = new Date();

    const session = await tx.authSession.findFirst({
      where: {
        id: sessionId,
        userId,
        sessionVersion: user.sessionVersion,
        revokedAt: null,
        expiresAt: { gt: now },
        absoluteExpiresAt: { gt: now },
      },
      select: { id: true },
    });

    if (!session) {
      throw new UnauthorizedException(
        'Session expired. Sign in again.',
      );
    }

    return user;
  }

  async request(
    userId: string,
    sessionId: string,
    emailInput: string,
    currentPassword: string,
    mfaCode?: string,
  ) {
    const newEmail =
      emailInput.trim().toLowerCase();

    if (
      !newEmail ||
      newEmail.length > 254 ||
      Buffer.byteLength(currentPassword, 'utf8') > 72
    ) {
      throw new BadRequestException(
        'Invalid email or password.',
      );
    }

    const snapshot = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        email: true,
        passwordHash: true,
        sessionVersion: true,
        emailVerifiedAt: true,
        isActive: true,
        _count: {
          select: {
            socialAccounts: true,
          },
        },
      },
    });

    if (
      !snapshot?.isActive ||
      !snapshot.emailVerifiedAt
    ) {
      throw new UnauthorizedException(
        'Sign in again.',
      );
    }

    if (
      !snapshot.passwordHash ||
      snapshot._count.socialAccounts !== 0
    ) {
      throw new BadRequestException(
        'Email changes for linked sign-in accounts are not supported yet.',
      );
    }

    if (
      !await compare(
        currentPassword,
        snapshot.passwordHash,
      )
    ) {
      throw new BadRequestException(
        'Current password is incorrect.',
      );
    }

    if (snapshot.email === newEmail) {
      throw new BadRequestException(
        'Choose a different email address.',
      );
    }

    if (
      !this.config.get<string>('RESEND_API_KEY')?.trim() ||
      !this.config.get<string>('RESET_EMAIL_FROM')?.trim()
    ) {
      throw new ServiceUnavailableException(
        'Email service is unavailable.',
      );
    }


    const requestId = randomUUID();

    const oldCode = randomInt(100000000)
      .toString()
      .padStart(8, '0');

    let newCode: string;

    do {
      newCode = randomInt(100000000)
        .toString()
        .padStart(8, '0');
    } while (newCode === oldCode);

    const expiresAt =
      await this.prisma.$transaction(async tx => {
        const user = await this.lockAccount(
          tx,
          userId,
          sessionId,
        );

        if (
          user.email !== snapshot.email ||
          user.passwordHash !== snapshot.passwordHash ||
          user.sessionVersion !== snapshot.sessionVersion
        ) {
          throw new ConflictException(
            'Account changed. Start again.',
          );
        }

        const existing = await tx.user.findUnique({
          where: { email: newEmail },
          select: { id: true },
        });

        if (existing) {
          throw new ConflictException(
            'Email address is unavailable.',
          );
        }

        const previous =
          await tx.emailChangeRequest.findUnique({
            where: { userId },
          });

        const now = new Date();

        if (
          previous &&
          now.getTime() - previous.sentAt.getTime() < MINUTE
        ) {
          throw new BadRequestException(
            'Wait 60 seconds before requesting new codes.',
          );
        }

        const sameWindow = Boolean(
          previous &&
          now.getTime() -
            previous.windowStartedAt.getTime() < HOUR,
        );

        const count =
          sameWindow && previous
            ? previous.sentInWindow
            : 0;

        if (count >= 5) {
          throw new BadRequestException(
            'Too many email change requests. Try again later.',
          );
        }

        const mfaValid =
          await this.mfa.verifySensitiveActionInTransaction(
            tx,
            userId,
            sessionId,
            snapshot.sessionVersion,
            mfaCode,
          );

        if (!mfaValid) {
          // Commit failed MFA attempts without
          // creating an email change request.
          return null;
        }

        const expiry = new Date(
          now.getTime() + 10 * MINUTE,
        );

        const data = {
          requestId,
          sessionId,
          sessionVersion: user.sessionVersion,
          oldEmail: user.email,
          newEmail,
          oldCodeHash: this.digest(
            userId,
            requestId,
            'old',
            oldCode,
          ),
          newCodeHash: this.digest(
            userId,
            requestId,
            'new',
            newCode,
          ),
          attempts: 0,
          sentAt: now,
          expiresAt: expiry,
          sentInWindow: count + 1,
          windowStartedAt:
            sameWindow && previous
              ? previous.windowStartedAt
              : now,
        };

        await tx.emailChangeRequest.upsert({
          where: { userId },
          create: { userId, ...data },
          update: data,
        });

        return expiry;
      });

    if (!expiresAt) {
      throw new BadRequestException(
        'A valid current authenticator code is required.',
      );
    }

    // Email delivery must occur outside database locks.

    const delivery = await Promise.allSettled([
      this.send(
        snapshot.email,
        'TED Education: Confirm email change',
        'Your current-email code is ' + oldCode +
        '. It expires in 10 minutes. ' +
        'If you did not request this change, secure your account.',
      ),

      this.send(
        newEmail,
        'TED Education: Verify new email',
        'Your new-email code is ' + newCode +
        '. It expires in 10 minutes.',
      ),
    ]);

    if (
      delivery.some(
        item => item.status === 'rejected',
      )
    ) {
      this.logger.warn(
        'Email change code delivery was not confirmed.',
      );

      throw new ServiceUnavailableException(
        'Code delivery was not confirmed. Wait 60 seconds and retry.',
      );
    }

    return {
      requestId,
      expiresAt,
      message: 'Verification codes sent.',
    };
  }

  async confirm(
    userId: string,
    sessionId: string,
    requestId: string,
    oldCode: string,
    newCode: string,
  ) {
    if (
      typeof oldCode !== 'string' ||
      typeof newCode !== 'string' ||
      oldCode.length !== 8 ||
      newCode.length !== 8 ||
      !/^[0-9]{8}$/.test(oldCode) ||
      !/^[0-9]{8}$/.test(newCode)
    ) {
      throw new BadRequestException(INVALID);
    }

    let oldEmail: string;

    try {
      oldEmail = await this.prisma.$transaction(async tx => {
        const user = await this.lockAccount(
          tx,
          userId,
          sessionId,
        );

        const record =
          await tx.emailChangeRequest.findUnique({
            where: { userId },
          });

        const now = new Date();

        if (
          !record ||
          record.requestId !== requestId ||
          record.sessionId !== sessionId ||
          record.sessionVersion !== user.sessionVersion ||
          record.oldEmail !== user.email ||
          record.expiresAt <= now ||
          record.attempts >= 5
        ) {
          throw new BadRequestException(INVALID);
        }

        const oldValid = this.matches(
          record.oldCodeHash,
          this.digest(
            userId,
            requestId,
            'old',
            oldCode,
          ),
        );

        const newValid = this.matches(
          record.newCodeHash,
          this.digest(
            userId,
            requestId,
            'new',
            newCode,
          ),
        );

        if (!oldValid || !newValid) {
          await tx.emailChangeRequest.update({
            where: { userId },
            data: {
              attempts: { increment: 1 },
            },
          });

          // Return rather than throw so attempts commit.
          return '';
        }

        const changed = await tx.user.updateMany({
          where: {
            id: userId,
            email: record.oldEmail,
            sessionVersion: record.sessionVersion,
            passwordHash: user.passwordHash,
            emailVerifiedAt: { not: null },
            isActive: true,
          },
          data: {
            email: record.newEmail,
            emailVerifiedAt: now,
            sessionVersion: { increment: 1 },
          },
        });

        if (changed.count !== 1) {
          throw new ConflictException(
            'Account changed. Start again.',
          );
        }

        await tx.authSession.updateMany({
          where: {
            userId,
            revokedAt: null,
          },
          data: { revokedAt: now },
        });

        await tx.passwordResetCode.deleteMany({
          where: { userId },
        });

        await tx.emailVerificationCode.updateMany({
          where: { userId },
          data: {
            attempts: 5,
          },
        });

        // Invalidate other outstanding sensitive actions.

        await tx.googleActionChallenge.updateMany({
          where: {
            userId,
            consumedAt: null,
          },
          data: {
            consumedAt: now,
          },
        });

        const consumed =
          await tx.emailChangeRequest.updateMany({
            where: {
              userId,
              requestId,
              sessionId,
              sessionVersion: record.sessionVersion,
              attempts: { lt: 5 },
              expiresAt: { gt: now },
            },
            data: {
              attempts: 5,
            },
          });

        if (consumed.count !== 1) {
          throw new BadRequestException(INVALID);
        }

        await tx.securityEvent.create({
          data: {
            userId,
            type: 'EMAIL_CHANGED',
          },
        });

        await enqueueSecurityNotification(
          tx,
          userId,
          'EMAIL_CHANGED',
          record.oldEmail,
        );

        await enqueueSecurityNotification(
          tx,
          userId,
          'EMAIL_CHANGED',
          record.newEmail,
        );

        return record.oldEmail;
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException(
          'Email address is unavailable.',
        );
      }

      throw error;
    }

    if (!oldEmail) {
      throw new BadRequestException(INVALID);
    }


    return {
      message: 'Email changed. Sign in again.',
    };
  }
}
