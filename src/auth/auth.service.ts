import { lockSecurityActivityUser } from './security/security-activity.service';
import { recordLimitedSecurityEvent } from './security/security-activity.service';
import { enqueueSecurityNotification } from '../notifications/security-notification.service';

import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Prisma, Role } from '@prisma/client';
import { compare, hash } from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';

import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { MfaService } from './mfa/mfa.service';
import { UpdateAccountDto } from './dto/update-account.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly mfa: MfaService,
  ) {}

  async login(dto: LoginDto) {
    const email = dto.email.trim().toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user || !user.isActive || !user.passwordHash ||
        !(await compare(dto.password, user.passwordHash))) {
      if (user?.isActive && user.passwordHash) {
        try {
          await this.prisma.$transaction(async tx => {
            await lockSecurityActivityUser(tx, user.id);

            const current = await tx.user.findFirst({
              where: {
                id: user.id,
                isActive: true,
                passwordHash: user.passwordHash,
                sessionVersion: user.sessionVersion,
              },
              select: { id: true },
            });

            if (current) {
              await recordLimitedSecurityEvent(
                tx,
                current.id,
                'PASSWORD_LOGIN_FAILED',
              );
            }
          }, {
            maxWait: 1000,
            timeout: 2000,
          });
        } catch {
          // Preserve the original authentication error.
          // Audit failure must not allow authentication.
        }
      }

      throw new UnauthorizedException('Invalid email or password.');
    }

    if (!user.emailVerifiedAt) {
      throw new ForbiddenException('Email verification required.');
    }

    return this.mfa.loginResult(user);
  }
  async register(dto: RegisterDto) {
    const email = dto.email.trim().toLowerCase();
    const fullName = dto.fullName.trim().replace(/\s+/g, ' ');

    if (fullName.length < 2) {
      throw new BadRequestException('Full name is required.');
    }

    if (Buffer.byteLength(dto.password, 'utf8') > 72) {
      throw new BadRequestException('Password is too long.');
    }

    const existing = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (existing) {
      throw new ConflictException('Email already registered.');
    }

    const passwordHash = await hash(dto.password, 12);

    try {
      return await this.prisma.user.create({
        data: {
          email,
          fullName,
          passwordHash,
          gender: dto.gender ?? null,
          role: Role.PATIENT,
        },
        select: {
          id: true,
          fullName: true,
          email: true,
          gender: true,
          role: true,
          createdAt: true,
        },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('Email already registered.');
      }

      throw error;
    }
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    sessionId: string,
    mfaCode?: string,
  ) {

    if (
      typeof newPassword !== 'string' ||
      Array.from(newPassword).length < 12 ||
      Buffer.byteLength(newPassword, 'utf8') > 72
    ) {
      throw new BadRequestException(
        'New password must contain at least 12 characters and at most 72 UTF-8 bytes.',
      );
    }

    if (
      typeof currentPassword !== 'string' ||
      !currentPassword ||
      Buffer.byteLength(currentPassword, 'utf8') > 72
    ) {
      throw new BadRequestException(
        'Current password is incorrect.',
      );
    }

    const snapshot = await this.prisma.user.findUnique({
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

    if (!snapshot?.isActive) {
      throw new UnauthorizedException(
        'Sign in again.',
      );
    }

    if (!snapshot.passwordHash) {
      throw new BadRequestException(
        'This account has no password. Use the linked sign-in provider.',
      );
    }

    if (!snapshot.emailVerifiedAt) {
      throw new BadRequestException(
        'Email verification is required.',
      );
    }

    const currentPasswordHash = snapshot.passwordHash;

    const valid = await compare(
      currentPassword,
      currentPasswordHash,
    );

    if (!valid) {
      throw new BadRequestException(
        'Current password is incorrect.',
      );
    }

    const reused = await compare(
      newPassword,
      currentPasswordHash,
    );

    if (reused) {
      throw new BadRequestException(
        'Choose a password different from the current one.',
      );
    }

    // Perform expensive hashing outside database locks.

    const passwordHash = await hash(
      newPassword,
      12,
    );

    const changed = await this.prisma.$transaction(
      async tx => {
        // Lock the account before checking the snapshot.

        await tx.$queryRaw`
          SELECT "id"
          FROM "User"
          WHERE "id" = ${userId}::uuid
          FOR UPDATE
        `;

        const current = await tx.user.findFirst({
          where: {
            id: userId,
            email: snapshot.email,
            isActive: true,
            passwordHash: currentPasswordHash,
            sessionVersion: snapshot.sessionVersion,
            emailVerifiedAt: { not: null },
          },
          select: {
            id: true,
          },
        });

        if (!current) {
          throw new ConflictException(
            'Account changed. Sign in again.',
          );
        }

        // Validate the active session and consume MFA
        // within this same database transaction.

        const mfaValid =
          await this.mfa.verifySensitiveActionInTransaction(
            tx,
            userId,
            sessionId,
            snapshot.sessionVersion,
            mfaCode,
          );

        if (!mfaValid) {
          // Return false rather than throwing so failed
          // MFA attempt counters can be committed.
          return false;
        }

        const now = new Date();

        const updated = await tx.user.updateMany({
          where: {
            id: userId,
            email: snapshot.email,
            isActive: true,
            passwordHash: currentPasswordHash,
            sessionVersion: snapshot.sessionVersion,
            emailVerifiedAt: { not: null },
          },
          data: {
            passwordHash,
            sessionVersion: { increment: 1 },
          },
        });

        if (updated.count !== 1) {
          throw new ConflictException(
            'Account changed. Sign in again.',
          );
        }

        // Recheck and revoke the requesting session.

        const currentSession =
          await tx.authSession.updateMany({
            where: {
              id: sessionId,
              userId,
              sessionVersion: snapshot.sessionVersion,
              revokedAt: null,
              expiresAt: { gt: now },
              absoluteExpiresAt: { gt: now },
            },
            data: {
              revokedAt: now,
            },
          });

        if (currentSession.count !== 1) {
          throw new UnauthorizedException(
            'Session expired. Sign in again.',
          );
        }

        // Revoke all other sessions.

        await tx.authSession.updateMany({
          where: {
            userId,
            revokedAt: null,
          },
          data: {
            revokedAt: now,
          },
        });

        // Remove obsolete password reset codes.
        // Account-level sending quota is preserved.

        await tx.passwordResetCode.deleteMany({
          where: { userId },
        });

        // Invalidate email verification codes without
        // deleting their sending-quota history.

        await tx.emailVerificationCode.updateMany({
          where: { userId },
          data: {
            attempts: 5,
          },
        });

        // Invalidate existing email change requests
        // while preserving their rate-limit history.

        await tx.emailChangeRequest.updateMany({
          where: { userId },
          data: {
            attempts: 5,
          },
        });

        // Invalidate outstanding Google action challenges
        // without resetting their rate-limit history.

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
            type: 'PASSWORD_CHANGED',
          },
        });

        await enqueueSecurityNotification(tx, userId, 'PASSWORD_CHANGED');

        return true;
      },
    );

    if (!changed) {
      throw new BadRequestException(
        'A valid current authenticator code is required.',
      );
    }


    return {
      message: 'Password changed. All sessions have been revoked.',
    };
  }

  async updateAccount(
    userId: string,
    dto: UpdateAccountDto,
    sessionId: string,
  ) {
    const values: Prisma.UserUpdateInput = {};

    if (dto.fullName !== undefined) {
      const name = dto.fullName.trim().replace(/\s+/g,' ');
      if (name.length < 2) {
        throw new BadRequestException('Name must contain at least 2 characters.');
      }
      values.fullName = name;
    }

    if (dto.gender !== undefined) values.gender = dto.gender;
    if (dto.preferredLanguage !== undefined)
      values.preferredLanguage = dto.preferredLanguage;
    if (dto.fontScale !== undefined)
      values.fontScale = dto.fontScale;
    if (dto.highContrast !== undefined)
      values.highContrast = dto.highContrast;
    if (dto.onboardingStep !== undefined)
      values.onboardingStep = dto.onboardingStep;

    if (dto.completeOnboarding === true) {
      values.onboardingStep = 3;
      values.onboardingCompletedAt = new Date();
    }

    return this.prisma.$transaction(async tx => {
      await lockSecurityActivityUser(tx, userId);

      const current = await tx.user.findUnique({
        where: { id: userId },
        select: {
          isActive: true,
          sessionVersion: true,
          passwordHash: true,
          emailVerifiedAt: true,
        },
      });

      if (
        !current?.isActive ||
        (current.passwordHash && !current.emailVerifiedAt)
      ) {
        throw new UnauthorizedException(
          'Sign in again.',
        );
      }

      await tx.$queryRaw`
        SELECT "id"
        FROM "AuthSession"
        WHERE "id" = ${sessionId}::uuid
          AND "userId" = ${userId}::uuid
        FOR UPDATE
      `;

      const now = new Date();

      const session = await tx.authSession.findFirst({
        where: {
          id: sessionId,
          userId,
          sessionVersion: current.sessionVersion,
          revokedAt: null,
          expiresAt: { gt: now },
          absoluteExpiresAt: { gt: now },
        },
        select: { id: true },
      });

      if (!session) {
        throw new UnauthorizedException(
          'Session expired or revoked. Sign in again.',
        );
      }

      return tx.user.update({
        where: { id: userId },
      data: values,
      select: {
        id: true, email: true, fullName: true, gender: true,
        role: true, preferredLanguage: true, fontScale: true,
        highContrast: true, onboardingStep: true,
        onboardingCompletedAt: true
      }
      });
    });
  }
}
