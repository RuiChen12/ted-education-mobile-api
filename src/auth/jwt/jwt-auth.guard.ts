import {
  JWT_ISSUER,
  JWT_AUDIENCE,
  JWT_ALGORITHM,
  UUID_V4_PATTERN,
  isSessionVersion,
} from './jwt.config';
import {
  CanActivate, ExecutionContext, Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp()
      .getRequest<Request & { user?: unknown; sessionId?: string }>();

    const authorization = req.headers.authorization;

    if (
      typeof authorization !== 'string' ||
      authorization.length > 8192
    ) {
      throw new UnauthorizedException();
    }

    const parts = authorization.split(' ');

    if (
      parts.length !== 2 ||
      parts[0].toLowerCase() !== 'bearer' ||
      !parts[1] ||
      /\s/.test(parts[1])
    ) {
      throw new UnauthorizedException();
    }

    const token = parts[1];

    let payload: {
      sub?: string;
      sid?: string;
      purpose?: string;
      sv?: number;
      exp?: number;
    };

    try {
      payload = await this.jwt.verifyAsync(token, {
        algorithms: [JWT_ALGORITHM],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    if (
      !payload ||
      typeof payload !== 'object' ||
      payload.purpose !== 'access' ||
      !isSessionVersion(payload.sv)
    ) {
      throw new UnauthorizedException(
        'Full authentication required.',
      );
    }

    if (
      typeof payload.sub !== 'string' ||
      !UUID_V4_PATTERN.test(payload.sub) ||
      typeof payload.sid !== 'string' ||
      !UUID_V4_PATTERN.test(payload.sid)
    ) {
      throw new UnauthorizedException();
    }

    const now = new Date();

    if (
      typeof payload.exp !== 'number' ||
      !Number.isSafeInteger(payload.exp) ||
      payload.exp <= Math.floor(now.getTime() / 1000)
    ) {
      throw new UnauthorizedException(
        'Invalid or expired token.',
      );
    }

    const session =
      await this.prisma.authSession.findUnique({
        where: { id: payload.sid },
        select: {
          userId: true,
          revokedAt: true,
          expiresAt: true,
          absoluteExpiresAt: true,
          devicePlatform: true,
          lastActiveAt: true,
          sessionVersion: true,
        },
      });

    if (
      !session ||
      session.userId !== payload.sub ||
      session.revokedAt ||
      session.expiresAt <= now ||
      session.absoluteExpiresAt <= now ||
      session.sessionVersion !== payload.sv
    ) {
      throw new UnauthorizedException(
        'Session revoked or expired.',
      );
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        email: true,
        fullName: true,
        gender: true,
        role: true,
        isActive: true,
        sessionVersion: true,
        passwordHash: true,
        emailVerifiedAt: true,
        preferredLanguage: true,
        fontScale: true,
        highContrast: true,
        onboardingStep: true,
        onboardingCompletedAt: true,
      },
    });

    if (!user || !user.isActive || user.sessionVersion !== payload.sv) {
      throw new UnauthorizedException();
    }

    if (user.passwordHash && !user.emailVerifiedAt) {
      throw new UnauthorizedException('Email verification required.');
    }

    const {
      isActive: _isActive,
      sessionVersion: _sessionVersion,
      passwordHash: _passwordHash,
      emailVerifiedAt: _emailVerifiedAt,
      ...safeUser
    } = user;
    const verifiedAt = new Date();

    if (
      session.expiresAt <= verifiedAt ||
      session.absoluteExpiresAt <= verifiedAt ||
      payload.exp <= Math.floor(verifiedAt.getTime() / 1000)
    ) {
      throw new UnauthorizedException(
        'Session revoked or expired.',
      );
    }

    // Device metadata is descriptive only.
    // Never use client-reported platform as authentication.

    const reportedPlatform =
      req.headers['x-ted-platform'];

    const platform =
      reportedPlatform === 'android' ||
      reportedPlatform === 'ios' ||
      reportedPlatform === 'web'
        ? reportedPlatform
        : null;

    const activityAt = new Date();

    const metadataMissing =
      !session.devicePlatform && platform !== null;

    const activityStale =
      !session.lastActiveAt ||
      activityAt.getTime() -
        session.lastActiveAt.getTime() >= 300000;

    if (metadataMissing || activityStale) {
      try {
        // Compare-and-set prevents concurrent requests
        // from overwriting newer session metadata.

        await this.prisma.authSession.updateMany({
          where: {
            id: payload.sid,
            userId: payload.sub,
            sessionVersion: user.sessionVersion,
            revokedAt: null,
            expiresAt: { gt: activityAt },
            absoluteExpiresAt: { gt: activityAt },
            devicePlatform: session.devicePlatform,
            lastActiveAt: session.lastActiveAt,
          },
          data: {
            ...(metadataMissing && platform
              ? { devicePlatform: platform }
              : {}),
            lastActiveAt: activityAt,
          },
        });
      } catch {
        // Optional activity tracking must not expose
        // database errors or invalidate valid credentials.
      }
    }

    const completedAt = new Date();

    if (
      session.expiresAt <= completedAt ||
      session.absoluteExpiresAt <= completedAt ||
      payload.exp <= Math.floor(completedAt.getTime() / 1000)
    ) {
      throw new UnauthorizedException(
        'Session revoked or expired.',
      );
    }

    req.user = safeUser;
    req.sessionId = payload.sid;
    return true;
  }
}
