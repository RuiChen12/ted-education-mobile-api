import { enqueueSecurityNotification } from '../../notifications/security-notification.service';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';

import { ConfigService } from '@nestjs/config';
import { Prisma, AuthProvider } from '@prisma/client';
import { OAuth2Client } from 'google-auth-library';
import { compare, hash } from 'bcryptjs';

import { PrismaService } from '../../prisma/prisma.service';
import { MfaService } from '../mfa/mfa.service';
import { GoogleActionChallengeService } from '../google/google-action-challenge.service';

@Injectable()
export class ConnectedAccountsService {
  private readonly google = new OAuth2Client();

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly mfa: MfaService,
    private readonly googleActions: GoogleActionChallengeService,
  ) {}

  async list(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        isActive: true,
        emailVerifiedAt: true,
        passwordHash: true,
        socialAccounts: {
          select: {
            provider: true,
            createdAt: true,
          },
        },
      },
    });

    if (!user?.isActive) {
      throw new UnauthorizedException('Sign in again.');
    }

    return {
      hasPassword: Boolean(user.passwordHash),
      canManageConnections: Boolean(
        user.passwordHash && user.emailVerifiedAt,
      ),
      canSetPassword: Boolean(
        !user.passwordHash &&
        user.socialAccounts.some(
          account => account.provider === AuthProvider.GOOGLE,
        ),
      ),
      providers: user.socialAccounts,
    };
  }

  private async verifyGoogle(idToken: string) {
    const audience = this.config
      .get<string>('GOOGLE_WEB_CLIENT_ID')
      ?.trim();

    if (!audience) {
      throw new ServiceUnavailableException(
        'Google sign-in is unavailable.',
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

    if (
      email.length > 254 ||
      (!email.endsWith('@gmail.com') && !payload.hd)
    ) {
      throw new BadRequestException(
        'An authoritative Google email is required.',
      );
    }

    return {
      subject: payload.sub,
      email,
    };
  }

  async requestGooglePasswordChallenge(
    userId: string,
    sessionId: string,
    idToken: string,
  ) {
    return this.googleActions.request(
      userId,
      sessionId,
      'SET_PASSWORD',
      idToken,
    );
  }

  async setGooglePassword(
    userId: string,
    sessionId: string,
    requestId: string,
    emailCode: string,
    newPassword: string,
    mfaCode?: string,
  ) {
    if (
      newPassword.length < 12 ||
      Buffer.byteLength(newPassword, 'utf8') > 72
    ) {
      throw new BadRequestException(
        'Password must contain at least 12 characters and at most 72 UTF-8 bytes.',
      );
    }

    const passwordHash = await hash(newPassword, 12);

    await this.googleActions.execute(
      {
        userId,
        sessionId,
        requestId,
        action: 'SET_PASSWORD',
        code: emailCode,
        mfaCode,
      },
      async (tx, identity) => {
        const now = new Date();

        const changed = await tx.user.updateMany({
          where: {
            id: identity.userId,
            email: identity.email,
            passwordHash: null,
            isActive: true,
            sessionVersion: identity.sessionVersion,
          },
          data: {
            passwordHash,
            emailVerifiedAt: now,
            sessionVersion: { increment: 1 },
          },
        });

        if (changed.count !== 1) {
          throw new ConflictException(
            'Account changed. Sign in again.',
          );
        }

        await tx.authSession.updateMany({
          where: {
            userId: identity.userId,
            revokedAt: null,
          },
          data: {
            revokedAt: now,
          },
        });

        await tx.passwordResetCode.deleteMany({
          where: { userId: identity.userId },
        });

        await tx.emailVerificationCode.updateMany({
          where: { userId: identity.userId },
          data: { attempts: 5 },
        });

        await tx.emailChangeRequest.updateMany({
          where: { userId: identity.userId },
          data: { attempts: 5 },
        });

        await tx.securityEvent.create({
          data: {
            userId: identity.userId,
            type: 'PASSWORD_CHANGED',
          },
        });

        await enqueueSecurityNotification(tx, identity.userId, 'PASSWORD_CHANGED');
      },
    );

    return {
      message:
        'Password configured. All sessions were revoked. Sign in again.',
    };
  }

  async changeGoogle(
    userId: string,
    sessionId: string,
    action: 'link' | 'unlink',
    password: string,
    mfaCode?: string,
    idToken?: string,
  ) {
    if (action !== 'link' && action !== 'unlink') {
      throw new BadRequestException(
        'Invalid account connection action.',
      );
    }

    const snapshot = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        email: true,
        isActive: true,
        passwordHash: true,
        emailVerifiedAt: true,
        sessionVersion: true,
      },
    });

    if (!snapshot?.isActive) {
      throw new UnauthorizedException('Sign in again.');
    }

    if (
      !snapshot.passwordHash ||
      !snapshot.emailVerifiedAt
    ) {
      throw new BadRequestException(
        'A verified password sign-in method is required.',
      );
    }

    if (
      Buffer.byteLength(password, 'utf8') > 72 ||
      !await compare(password, snapshot.passwordHash)
    ) {
      throw new BadRequestException(
        'Current password is incorrect.',
      );
    }

    let identity:
      { subject: string; email: string } |
      undefined;

    if (action === 'link') {
      if (!idToken) {
        throw new BadRequestException(
          'Google identity is required.',
        );
      }

      identity = await this.verifyGoogle(idToken);

      if (identity.email !== snapshot.email) {
        throw new BadRequestException(
          'Google email must match your verified TED email.',
        );
      }
    }


    try {
      const changed = await this.prisma.$transaction(async tx => {
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
            isActive: true,
            passwordHash: true,
            emailVerifiedAt: true,
            sessionVersion: true,
          },
        });

        if (
          !user?.isActive ||
          !user.passwordHash ||
          !user.emailVerifiedAt ||
          user.email !== snapshot.email ||
          user.passwordHash !== snapshot.passwordHash ||
          user.sessionVersion !== snapshot.sessionVersion
        ) {
          throw new ConflictException(
            'Account changed. Sign in again.',
          );
        }

        const now = new Date();

        const session = await tx.authSession.findFirst({
          where: {
            id: sessionId,
            userId,
            revokedAt: null,
            sessionVersion: user.sessionVersion,
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

        const mfaValid =
          await this.mfa.verifySensitiveActionInTransaction(
            tx,
            userId,
            sessionId,
            snapshot.sessionVersion,
            mfaCode,
          );

        if (!mfaValid) {
          // Preserve failed MFA attempts without changing
          // the connected account or session state.
          return false;
        }

        const existing =
          await tx.socialAccount.findUnique({
            where: {
              userId_provider: {
                userId,
                provider: AuthProvider.GOOGLE,
              },
            },
          });

        if (action === 'link') {
          if (!identity || identity.email !== user.email) {
            throw new BadRequestException(
              'Google identity does not match.',
            );
          }

          if (existing) {
            throw new ConflictException(
              'A Google account is already connected.',
            );
          }

          await tx.socialAccount.create({
            data: {
              userId,
              provider: AuthProvider.GOOGLE,
              providerUserId: identity.subject,
            },
          });
        } else {
          if (!existing) {
            throw new BadRequestException(
              'Google is not connected.',
            );
          }

          await tx.socialAccount.delete({
            where: { id: existing.id },
          });
        }

        const updated = await tx.user.updateMany({
          where: {
            id: userId,
            email: snapshot.email,
            isActive: true,
            passwordHash: snapshot.passwordHash,
            emailVerifiedAt: { not: null },
            sessionVersion: snapshot.sessionVersion,
          },
          data: {
            sessionVersion: { increment: 1 },
          },
        });

        if (updated.count !== 1) {
          throw new ConflictException(
            'Account changed. Sign in again.',
          );
        }

        await tx.authSession.updateMany({
          where: {
            userId,
            revokedAt: null,
          },
          data: {
            revokedAt: now,
          },
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

        await tx.emailChangeRequest.updateMany({
          where: { userId },
          data: {
            attempts: 5,
          },
        });

        await tx.googleActionChallenge.updateMany({
          where: {
            userId,
            consumedAt: null,
          },
          data: {
            consumedAt: now,
          },
        });

        await tx.securityEvent.create({
          data: {
            userId,
            type: action === 'link'
              ? 'GOOGLE_LINKED'
              : 'GOOGLE_UNLINKED',
          },
        });

        await enqueueSecurityNotification(
          tx,
          userId,
          action === 'link' ? 'GOOGLE_LINKED' : 'GOOGLE_UNLINKED',
        );
        return true;
      });

      if (!changed) {
        throw new BadRequestException(
          'A valid current authenticator code is required.',
        );
      }
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException(
          'This Google identity is already connected.',
        );
      }

      throw error;
    }

    return {
      message: 'Connection updated. Sign in again.',
    };
  }
}
