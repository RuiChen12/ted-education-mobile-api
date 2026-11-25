import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';

import type { Prisma } from '@prisma/client';
import { compare } from 'bcryptjs';

import { PrismaService } from '../../prisma/prisma.service';
import { MfaService } from '../mfa/mfa.service';
import { GoogleActionChallengeService } from '../google/google-action-challenge.service';

import {
  ExportAccountDataDto,
  DeleteAccountDto,
  GoogleDataChallengeDto,
  GoogleExportAccountDataDto,
  GoogleDeleteAccountDto,
} from '../dto/account-data.dto';

export type AuthRequest = {
  user: { id: string };
  sessionId: string;
};

type DataAuthorization = {
  passwordHash: string | null;
  sessionVersion: number;
};

@Injectable()
export class AccountDataService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly mfa: MfaService,
    private readonly googleActions: GoogleActionChallengeService,
  ) {}





  async exportAccount(
     req: AuthRequest,
     dto: ExportAccountDataDto,
  ) {

    const userId = req.user.id;

    const snapshot = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        passwordHash: true,
        sessionVersion: true,
        isActive: true,
        emailVerifiedAt: true,
        role: true,
      },
    });

    if (!snapshot?.isActive) {
      throw new UnauthorizedException(
        'Sign in again.',
      );
    }

    if (
      !snapshot.passwordHash ||
      !snapshot.emailVerifiedAt
    ) {
      throw new BadRequestException(
        'Verified password authentication is required.',
      );
    }

    const passwordHash = snapshot.passwordHash;

    if (
      typeof dto.currentPassword !== 'string' ||
      !dto.currentPassword ||
      Buffer.byteLength(dto.currentPassword, 'utf8') > 72 ||
      !await compare(dto.currentPassword, passwordHash)
    ) {
      throw new BadRequestException(
        'Current password is incorrect.',
      );
    }

    const authorization = {
      passwordHash,
      sessionVersion: snapshot.sessionVersion,
    };

    const result = await this.prisma.$transaction(
      async tx => {

        const mfaValid =
          await this.mfa.verifySensitiveActionInTransaction(
            tx,
            userId,
            req.sessionId,
            authorization.sessionVersion,
            dto.mfaCode,
          );

        if (!mfaValid) {
          return null;
        }

        return this.buildAccountExport(
          tx,
          req,
          authorization,
        );
      },
      {
        isolationLevel: 'RepeatableRead',
      },
    );

    if (result === null) {
      throw new BadRequestException(
        'A valid current authenticator code is required.',
      );
    }

    return result;
  }





  async deleteAccount(
     req: AuthRequest,
     dto: DeleteAccountDto,
  ) {
    if (dto.confirmation !== 'DELETE') {
      throw new BadRequestException(
        'Account deletion requires explicit confirmation.',
      );
    }


    const userId = req.user.id;

    const snapshot = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        passwordHash: true,
        sessionVersion: true,
        isActive: true,
        emailVerifiedAt: true,
        role: true,
      },
    });

    if (!snapshot?.isActive) {
      throw new UnauthorizedException(
        'Sign in again.',
      );
    }

    if (
      !snapshot.passwordHash ||
      !snapshot.emailVerifiedAt
    ) {
      throw new BadRequestException(
        'Verified password authentication is required.',
      );
    }

    const passwordHash = snapshot.passwordHash;

    if (
      typeof dto.currentPassword !== 'string' ||
      !dto.currentPassword ||
      Buffer.byteLength(dto.currentPassword, 'utf8') > 72 ||
      !await compare(dto.currentPassword, passwordHash)
    ) {
      throw new BadRequestException(
        'Current password is incorrect.',
      );
    }

    const authorization = {
      passwordHash,
      sessionVersion: snapshot.sessionVersion,
    };

    if (snapshot.role !== 'PATIENT') {
      throw new BadRequestException(
        'Contact support to delete this account.',
      );
    }

    const result = await this.prisma.$transaction(
      async tx => {

        const mfaValid =
          await this.mfa.verifySensitiveActionInTransaction(
            tx,
            userId,
            req.sessionId,
            authorization.sessionVersion,
            dto.mfaCode,
          );

        if (!mfaValid) {
          return null;
        }

        const avatarCleanupQueued =
          await this.performAccountDeletion(
            tx,
            req,
            authorization,
          );

        return { avatarCleanupQueued };
      },
    );

    if (result === null) {
      throw new BadRequestException(
        'A valid current authenticator code is required.',
      );
    }

    return {
      accountDeleted: true,
      avatarCleanupQueued: result.avatarCleanupQueued,
      message: 'Account deleted.',
    };
  }


  private async buildAccountExport(
    tx: Prisma.TransactionClient,
    req: AuthRequest,
    snapshot: DataAuthorization,
  ) {
    const userId = req.user.id;

    const now = new Date();

    const user = await tx.user.findFirst({
      where: {
        id: userId,
        isActive: true,
        sessionVersion: snapshot.sessionVersion,
        passwordHash: snapshot.passwordHash,
        ...(snapshot.passwordHash !== null
          ? { emailVerifiedAt: { not: null } }
          : {}),
      },
      select: {
        id: true,
        email: true,
        fullName: true,
        gender: true,
        role: true,
        preferredLanguage: true,
        fontScale: true,
        highContrast: true,
        onboardingStep: true,
        onboardingCompletedAt: true,
        emailVerifiedAt: true,
        createdAt: true,
        updatedAt: true,

        socialAccounts: {
          select: {
            provider: true,
            createdAt: true,
          },
        },

        mfaSetting: {
          select: {
            enabledAt: true,
          },
        },
      },
    });

    if (!user) {
      throw new UnauthorizedException(
        'Account changed. Sign in again.',
      );
    }

    const currentSession =
      await tx.authSession.findFirst({
        where: {
          id: req.sessionId,
          userId,
          sessionVersion: snapshot.sessionVersion,
          revokedAt: null,
          expiresAt: { gt: now },
          absoluteExpiresAt: { gt: now },
        },
        select: { id: true },
      });

    if (!currentSession) {
      throw new UnauthorizedException(
        'Session expired. Sign in again.',
      );
    }

    const sessions =
      await tx.authSession.findMany({
        where: { userId },
        orderBy: [
          { createdAt: 'desc' },
          { id: 'desc' },
        ],
        take: 201,
        select: {
          createdAt: true,
          updatedAt: true,
          expiresAt: true,
          absoluteExpiresAt: true,
          revokedAt: true,
          devicePlatform: true,
          lastActiveAt: true,
        },
      });

    const events =
      await tx.securityEvent.findMany({
        where: {
          userId,
          createdAt: {
            gte: new Date(
              now.getTime() - 90 * 24 * 60 * 60 * 1000,
            ),
          },
        },
        orderBy: [
          { createdAt: 'desc' },
          { id: 'desc' },
        ],
        take: 1001,
        select: {
          type: true,
          createdAt: true,
        },
      });

    const {
      socialAccounts,
      mfaSetting,
      ...profile
    } = user;

    return {
      formatVersion: 2,

      exportedAt: now.toISOString(),

      scope: 'account-data-only',

      limits: {
        maximumSessions: 200,
        maximumSecurityEvents: 1000,
        securityEventWindowDays: 90,
      },

      account: profile,

      connectedAccounts: socialAccounts,

      security: {
        mfaEnabled: Boolean(
          mfaSetting?.enabledAt,
        ),

        mfaEnabledAt:
          mfaSetting?.enabledAt ?? null,

        sessions: sessions.slice(0, 200),

        recentEvents: events.slice(0, 1000),
      },

      completeness: {
        sessionsTruncated:
          sessions.length > 200,

        eventsTruncated:
          events.length > 1000,

        medicalRecordsIncluded: false,

        avatarFileIncluded: false,
      },
    };
  }

  private async performAccountDeletion(
    tx: Prisma.TransactionClient,
    req: AuthRequest,
    snapshot: DataAuthorization,
  ) {
    const userId = req.user.id;

    await tx.$queryRaw`
      SELECT "id"
      FROM "User"
      WHERE "id" = ${userId}::uuid
      FOR UPDATE
    `;

    await tx.$queryRaw`
      SELECT "id"
      FROM "AuthSession"
      WHERE "id" = ${req.sessionId}::uuid
        AND "userId" = ${userId}::uuid
      FOR UPDATE
    `;

    const user = await tx.user.findFirst({
      where: {
        id: userId,
        isActive: true,
        role: 'PATIENT',
        passwordHash: snapshot.passwordHash,
        sessionVersion: snapshot.sessionVersion,
        ...(snapshot.passwordHash !== null
          ? { emailVerifiedAt: { not: null } }
          : {}),
      },
      select: {
        id: true,
        avatarUrl: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException(
        'Account changed. Sign in again.',
      );
    }

    const now = new Date();

    const session = await tx.authSession.findFirst({
      where: {
        id: req.sessionId,
        userId,
        sessionVersion: snapshot.sessionVersion,
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

    if (user.avatarUrl) {
      const uuid =
        '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';

      const managedKey = new RegExp(
        '^avatars/' + uuid + '/' + uuid + '\\.jpg$',
        'i',
      );

      if (
        !managedKey.test(user.avatarUrl) ||
        !user.avatarUrl.startsWith(
          'avatars/' + userId + '/',
        )
      ) {
        throw new BadRequestException(
          'Avatar storage requires manual review. Contact support.',
        );
      }

      await tx.avatarCleanupJob.upsert({
        where: {
          objectKey: user.avatarUrl,
        },
        create: {
          objectKey: user.avatarUrl,
          notBefore: now,
        },
        update: {},
      });
    }

    await tx.user.delete({
      where: { id: userId },
    });

    return Boolean(user.avatarUrl);
  }





  async requestGoogleDataChallenge(
     req: AuthRequest,
     dto: GoogleDataChallengeDto,
  ) {
    if (dto.action === 'DELETE_ACCOUNT') {
      const user = await this.prisma.user.findUnique({
        where: { id: req.user.id },
        select: {
          role: true,
          isActive: true,
        },
      });

      if (!user?.isActive) {
        throw new UnauthorizedException(
          'Sign in again.',
        );
      }

      if (user.role !== 'PATIENT') {
        throw new BadRequestException(
          'Contact support to delete this account.',
        );
      }
    }

    return this.googleActions.request(
      req.user.id,
      req.sessionId,
      dto.action,
      dto.idToken,
    );
  }





  async exportGoogleAccount(
     req: AuthRequest,
     dto: GoogleExportAccountDataDto,
  ) {
    return this.googleActions.execute(
      {
        userId: req.user.id,
        sessionId: req.sessionId,
        requestId: dto.requestId,
        action: 'EXPORT_DATA',
        code: dto.emailCode,
        mfaCode: dto.mfaCode,
      },
      async (tx, identity) => {
        return this.buildAccountExport(
          tx,
          req,
          {
            passwordHash: null,
            sessionVersion: identity.sessionVersion,
          },
        );
      },
    );
  }





  async deleteGoogleAccount(
     req: AuthRequest,
     dto: GoogleDeleteAccountDto,
  ) {
    if (dto.confirmation !== 'DELETE') {
      throw new BadRequestException(
        'Account deletion requires explicit confirmation.',
      );
    }

    const avatarCleanupQueued =
      await this.googleActions.execute(
        {
          userId: req.user.id,
          sessionId: req.sessionId,
          requestId: dto.requestId,
          action: 'DELETE_ACCOUNT',
          code: dto.emailCode,
          mfaCode: dto.mfaCode,
        },
        async (tx, identity) => {
          return this.performAccountDeletion(
            tx,
            req,
            {
              passwordHash: null,
              sessionVersion: identity.sessionVersion,
            },
          );
        },
      );

    return {
      accountDeleted: true,
      avatarCleanupQueued,
      message: 'Account deleted.',
    };
  }

}
