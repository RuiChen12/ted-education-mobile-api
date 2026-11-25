import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';

import { ConfigService } from '@nestjs/config';

import {
  AuthProvider,
  GoogleSensitiveAction,
  Prisma,
} from '@prisma/client';

import { OAuth2Client } from 'google-auth-library';

import {
  createHmac,
  randomInt,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';

import { PrismaService } from '../../prisma/prisma.service';
import { MfaService } from '../mfa/mfa.service';
import { UUID_V4_PATTERN } from '../jwt/jwt.config';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

const MAX_ATTEMPTS = 5;
const MAX_SENDS = 5;
const CODE_LIFETIME = 10 * MINUTE;

const INVALID =
  'Invalid or expired verification request.';

type ChallengeBinding = {
  userId: string;
  requestId: string;
  sessionId: string;
  sessionVersion: number;
  action: GoogleSensitiveAction;
  googleSubject: string;
  email: string;
};

type ChallengeInput = {
  userId: string;
  sessionId: string;
  requestId: string;
  action: GoogleSensitiveAction;
  code: string;
  mfaCode?: string;
};

const ACTION_LABELS: Record<
  GoogleSensitiveAction,
  string
> = {
  SET_PASSWORD: 'set your TED password',
  EXPORT_DATA: 'export your account data',
  DELETE_ACCOUNT: 'delete your TED account',
};

@Injectable()
export class GoogleActionChallengeService {
  private readonly google = new OAuth2Client();

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly mfa: MfaService,
  ) {}

  private digest(
    binding: ChallengeBinding,
    code: string,
  ): string {
    return createHmac(
      'sha256',
      this.config.getOrThrow<string>(
        'PASSWORD_RESET_SECRET',
      ),
    )
      .update(JSON.stringify([
        'ted:google-action:v1',
        binding.userId,
        binding.requestId,
        binding.sessionId,
        binding.sessionVersion,
        binding.action,
        binding.googleSubject,
        binding.email,
        code,
      ]))
      .digest('hex');
  }

  private matches(a: string, b: string): boolean {
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

  private async verifyGoogle(idToken: string) {
    const audience = this.config
      .get<string>('GOOGLE_WEB_CLIENT_ID')
      ?.trim();

    if (!audience) {
      throw new ServiceUnavailableException(
        'Google verification is unavailable.',
      );
    }

    if (
      typeof idToken !== 'string' ||
      idToken.length < 20 ||
      idToken.length > 8192
    ) {
      throw new BadRequestException(
        'Invalid Google credential.',
      );
    }

    let payload;

    try {
      const ticket = await this.google.verifyIdToken({
        idToken,
        audience,
      });

      payload = ticket.getPayload();
    } catch {
      throw new BadRequestException(
        'Google identity verification failed.',
      );
    }

    if (
      !payload?.sub ||
      payload.sub.length > 255 ||
      !payload.email ||
      payload.email_verified !== true
    ) {
      throw new BadRequestException(
        'Google identity could not be verified.',
      );
    }

    const email = payload.email.trim().toLowerCase();

    if (!email || email.length > 254) {
      throw new BadRequestException(
        'Invalid Google account email.',
      );
    }

    return {
      subject: payload.sub,
      email,
    };
  }

  private async lockAccount(
    tx: Prisma.TransactionClient,
    userId: string,
    sessionId: string,
  ) {
    if (
      !UUID_V4_PATTERN.test(userId) ||
      !UUID_V4_PATTERN.test(sessionId)
    ) {
      throw new UnauthorizedException('Sign in again.');
    }

    // Always acquire the User lock before AuthSession.
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
        id: true,
        email: true,
        role: true,
        isActive: true,
        passwordHash: true,
        emailVerifiedAt: true,
        sessionVersion: true,
      },
    });

    if (!user?.isActive) {
      throw new UnauthorizedException(
        'Sign in again.',
      );
    }

    if (user.passwordHash) {
      throw new BadRequestException(
        'Use password-based verification for this account.',
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
      select: {
        id: true,
      },
    });

    if (!session) {
      throw new UnauthorizedException(
        'Session expired. Sign in again.',
      );
    }

    const google = await tx.socialAccount.findUnique({
      where: {
        userId_provider: {
          userId,
          provider: AuthProvider.GOOGLE,
        },
      },
      select: {
        providerUserId: true,
      },
    });

    if (!google) {
      throw new BadRequestException(
        'No linked Google account was found.',
      );
    }

    return {
      user,
      subject: google.providerUserId,
    };
  }

  private async sendCode(
    email: string,
    action: GoogleSensitiveAction,
    code: string,
  ): Promise<void> {
    const key = this.config
      .get<string>('RESEND_API_KEY')
      ?.trim();

    const from = this.config
      .get<string>('RESET_EMAIL_FROM')
      ?.trim();

    if (!key || !from) {
      throw new ServiceUnavailableException(
        'Email verification is unavailable.',
      );
    }

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
            to: [email],
            subject: 'TED Education: Security verification',
            text: [
              'A request was made to ' +
                ACTION_LABELS[action] + '.',
              '',
              'Your verification code is: ' + code,
              '',
              'This code expires in 10 minutes.',
              'Do not share this code with anyone.',
              'If you did not request this, ignore this email.',
            ].join('\n'),
          }),
          signal: AbortSignal.timeout(5000),
        },
      );

      if (!response.ok) {
        throw new Error('Email delivery failed.');
      }
    } catch {
      throw new ServiceUnavailableException(
        'Verification email delivery could not be confirmed.',
      );
    }
  }

  async request(
    userId: string,
    sessionId: string,
    action: GoogleSensitiveAction,
    idToken: string,
  ) {
    if (
      !Object.values(GoogleSensitiveAction).includes(action)
    ) {
      throw new BadRequestException(
        'Invalid verification action.',
      );
    }

    const identity = await this.verifyGoogle(idToken);

    const code = randomInt(0, 100_000_000)
      .toString()
      .padStart(8, '0');

    const requestId = randomUUID();

    const challenge = await this.prisma.$transaction(
      async tx => {
        const account = await this.lockAccount(
          tx,
          userId,
          sessionId,
        );

        if (
          identity.subject !== account.subject ||
          identity.email !== account.user.email
        ) {
          throw new BadRequestException(
            'Google identity does not match this account.',
          );
        }

        if (action === 'DELETE_ACCOUNT') {
          const eligible = await tx.user.findFirst({
            where: {
              id: userId,
              isActive: true,
              role: 'PATIENT',
            },
            select: { id: true },
          });

          if (!eligible) {
            throw new BadRequestException(
              'Contact support to delete this account.',
            );
          }
        }

        const now = new Date();

        const previous =
          await tx.googleActionChallenge.findUnique({
            where: { userId },
          });

        if (
          previous &&
          now.getTime() - previous.sentAt.getTime() < MINUTE
        ) {
          throw new HttpException(
            'Wait 60 seconds before requesting another code.',
            HttpStatus.TOO_MANY_REQUESTS,
          );
        }

        const sameWindow = Boolean(
          previous &&
          now.getTime() -
            previous.windowStartedAt.getTime() < HOUR,
        );

        if (
          previous &&
          sameWindow &&
          previous.sentInWindow >= MAX_SENDS
        ) {
          throw new HttpException(
            'Too many verification requests. Try again later.',
            HttpStatus.TOO_MANY_REQUESTS,
          );
        }

        const binding: ChallengeBinding = {
          userId,
          requestId,
          sessionId,
          sessionVersion: account.user.sessionVersion,
          action,
          googleSubject: account.subject,
          email: account.user.email,
        };

        const expiresAt = new Date(
          now.getTime() + CODE_LIFETIME,
        );

        const data = {
          ...binding,
          codeHash: this.digest(binding, code),
          attempts: 0,
          consumedAt: null,
          sentAt: now,
          expiresAt,
          sentInWindow:
            previous && sameWindow
              ? previous.sentInWindow + 1
              : 1,
          windowStartedAt:
            previous && sameWindow
              ? previous.windowStartedAt
              : now,
        };

        await tx.googleActionChallenge.upsert({
          where: { userId },
          create: data,
          update: data,
        });

        return {
          requestId,
          email: binding.email,
          expiresAt,
        };
      },
    );

    // Never perform external email calls inside a DB transaction.
    try {
      await this.sendCode(
        challenge.email,
        action,
        code,
      );
    } catch (error) {
      // Invalidate only this request and preserve rate limits.
      await this.prisma.googleActionChallenge.updateMany({
        where: {
          userId,
          requestId,
          consumedAt: null,
        },
        data: {
          consumedAt: new Date(),
        },
      });

      throw error;
    }

    return {
      requestId: challenge.requestId,
      expiresAt: challenge.expiresAt.toISOString(),
      message: 'Verification code sent.',
    };
  }

  private async check(
    tx: Prisma.TransactionClient,
    input: ChallengeInput,
  ) {
    const account = await this.lockAccount(
      tx,
      input.userId,
      input.sessionId,
    );

    const record =
      await tx.googleActionChallenge.findUnique({
        where: { userId: input.userId },
      });

    if (
      !record ||
      record.requestId !== input.requestId ||
      record.sessionId !== input.sessionId ||
      record.sessionVersion !== account.user.sessionVersion ||
      record.action !== input.action ||
      record.googleSubject !== account.subject ||
      record.email !== account.user.email ||
      record.consumedAt ||
      record.expiresAt <= new Date() ||
      record.attempts >= MAX_ATTEMPTS
    ) {
      return null;
    }

    const expected = this.digest(record, input.code);

    if (!this.matches(record.codeHash, expected)) {
      await tx.googleActionChallenge.updateMany({
        where: {
          userId: input.userId,
          requestId: input.requestId,
          consumedAt: null,
          attempts: { lt: MAX_ATTEMPTS },
        },
        data: {
          attempts: { increment: 1 },
        },
      });

      // Returning null commits the failed attempt.
      // Throwing here would roll it back.
      return null;
    }

    return {
      record,
      account,
    };
  }

  async execute<T>(
    input: ChallengeInput,
    operation: (
      tx: Prisma.TransactionClient,
      identity: {
        userId: string;
        email: string;
        googleSubject: string;
        sessionVersion: number;
      },
    ) => Promise<T>,
  ): Promise<T> {
    if (
      !UUID_V4_PATTERN.test(input.requestId) ||
      !Object.values(GoogleSensitiveAction).includes(input.action) ||
      typeof input.code !== 'string' ||
      input.code.length !== 8 ||
      !/^[0-9]{8}$/.test(input.code)
    ) {
      throw new BadRequestException(INVALID);
    }

    const result = await this.prisma.$transaction(
      async tx => {
        // check() locks the account and current session.
        // Failed email-code attempts must commit.

        const checked = await this.check(tx, input);

        if (!checked) {
          return { ok: false as const };
        }

        if (input.action === 'DELETE_ACCOUNT') {
          const eligible = await tx.user.findFirst({
            where: {
              id: input.userId,
              isActive: true,
              role: 'PATIENT',
            },
            select: { id: true },
          });

          if (!eligible) {
            throw new BadRequestException(
              'Contact support to delete this account.',
            );
          }
        }

        const mfaValid =
          await this.mfa.verifySensitiveActionInTransaction(
            tx,
            input.userId,
            input.sessionId,
            checked.record.sessionVersion,
            input.mfaCode,
          );

        if (!mfaValid) {
          return {
            ok: false as const,
            reason: 'MFA' as const,
          };
        }

        const now = new Date();

        const consumed =
          await tx.googleActionChallenge.updateMany({
            where: {
              userId: input.userId,
              requestId: input.requestId,
              consumedAt: null,
              expiresAt: { gt: now },
              attempts: { lt: MAX_ATTEMPTS },
            },
            data: {
              consumedAt: now,
            },
          });

        if (consumed.count !== 1) {
          throw new BadRequestException(INVALID);
        }

        // The operation must use this transaction client.
        // Do not perform external network calls here.
        const value = await operation(tx, {
          userId: input.userId,
          email: checked.record.email,
          googleSubject: checked.record.googleSubject,
          sessionVersion: checked.record.sessionVersion,
        });

        return {
          ok: true as const,
          value,
        };
      },
      {
        isolationLevel:
          input.action === 'EXPORT_DATA'
            ? 'RepeatableRead'
            : 'ReadCommitted',
      },
    );

    if (!result.ok) {
      if ('reason' in result && result.reason === 'MFA') {
        throw new BadRequestException(
          'A valid current authenticator code is required.',
        );
      }

      throw new BadRequestException(INVALID);
    }

    return result.value;
  }
}
