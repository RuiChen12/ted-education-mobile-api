import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  BadRequestException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import { createHmac } from 'node:crypto';

import { AuthController } from './auth.controller';
import { AuthSessionController } from './sessions/auth-session.controller';
import { AuthSessionService } from './sessions/auth-session.service';
import { EmailVerificationService } from './email/email-verification.service';
import { JwtAuthGuard } from './jwt/jwt-auth.guard';

const SID = '11111111-1111-4111-8111-111111111111';
const UID = '22222222-2222-4222-8222-222222222222';
const EMAIL = 'test@example.com';
const SECRET = 'test-only-coverage-secret';
const TOKEN = SID + '.' + 'A'.repeat(43);
const DAY = 86400000;
const CODE = '12345678';

const TOKEN_HASH = createHmac('sha256', SECRET)
  .update('ted:refresh:' + TOKEN)
  .digest('hex');

const SENT_AT = new Date(Date.now() - 120000);
const CODE_HASH = createHmac('sha256', SECRET)
  .update(JSON.stringify(['ted:verify-email:v2', UID, EMAIL, 3, SENT_AT.toISOString(), CODE])).digest('hex');

function validSession() {
  return {
    id: SID,
    userId: UID,
    tokenHash: TOKEN_HASH,
    sessionVersion: 3,
    revokedAt: null as Date | null,
    expiresAt: new Date(Date.now() + DAY),
    absoluteExpiresAt: new Date(Date.now() + 20 * DAY),
    user: {
      id: UID,
      isActive: true,
      sessionVersion: 3,
      passwordHash: null as string | null,
      emailVerifiedAt: new Date() as Date | null,
    },
  };
}

function sessionHarness() {
  const owner = vi.fn().mockResolvedValue(validSession());
  const tx = {
    $queryRaw: vi.fn().mockResolvedValue([]),
    user: { findUnique: vi.fn(async () => (await owner())?.user) },
    authSession: { findFirst: vi.fn(async () => owner()), create: vi.fn().mockResolvedValue({}), updateMany: vi.fn().mockResolvedValue({ count: 1 }), deleteMany: vi.fn().mockResolvedValue({ count: 1 }) },
    usedRefreshToken: { create: vi.fn().mockResolvedValue({}), findUnique: vi.fn().mockResolvedValue(null) },
    securityEvent: { create: vi.fn().mockResolvedValue({}) },
  };
  const prisma = { ...tx, authSession: { ...tx.authSession, findUnique: owner }, $transaction: vi.fn(async (fn: (client: typeof tx) => Promise<unknown>) => fn(tx)) };
  const jwt = { signAsync: vi.fn().mockResolvedValue('signed-access') };
  const config = { getOrThrow: vi.fn().mockReturnValue(SECRET) };
  const service = new AuthSessionService(prisma as never, jwt as never, config as never);
  return { service, prisma, jwt, tx };
}

function validUser() {
  return {
    id: UID,
    isActive: true,
    passwordHash: 'hashed-password' as string | null,
    email: EMAIL, sessionVersion: 3,
    emailVerifiedAt: null as Date | null,
  };
}

function validRecord() {
  return {
    userId: UID,
    codeHash: CODE_HASH, sentAt: SENT_AT, sentInWindow: 1, windowStartedAt: SENT_AT,
    attempts: 0,
    expiresAt: new Date(Date.now() + 600000),
  };
}

function emailHarness() {
  const tx = {
    $queryRaw: vi.fn().mockResolvedValue([]),
    user: { findUnique: vi.fn().mockResolvedValue(validUser()), updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    emailVerificationCode: { findUnique: vi.fn().mockResolvedValue(validRecord()), updateMany: vi.fn().mockResolvedValue({ count: 1 }), upsert: vi.fn().mockResolvedValue({}) },
  };
  const owner = vi.fn().mockResolvedValue(validUser());
  tx.user.findUnique.mockImplementation(async () => owner());
  const prisma = { ...tx, user: { ...tx.user, findUnique: owner }, $transaction: vi.fn(async (fn: (client: typeof tx) => Promise<unknown>) => fn(tx)) };
  const config = { get: vi.fn((key: string): string | undefined => key === 'RESEND_API_KEY' ? 'test-api-key' : key === 'RESET_EMAIL_FROM' ? 'verify@example.com' : undefined), getOrThrow: vi.fn().mockReturnValue(SECRET) };
  const service = new EmailVerificationService(prisma as never, config as never);
  return { service, prisma, config, tx };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// ============================================
// CONTROLLER COVERAGE
// ============================================

describe('Auth controller route coverage', () => {
  it('delegates email request and confirmation', async () => {
    const emailVerification = {
      requestCode: vi.fn().mockResolvedValue({
        message: 'requested',
      }),
      confirmCode: vi.fn().mockResolvedValue({
        message: 'confirmed',
      }),
    };

    const controller = new AuthController(
      {} as never,
      {} as never,
      {} as never,
      emailVerification as never,
    );

    await expect(
      controller.requestEmailVerification({ email: EMAIL }),
    ).resolves.toEqual({ message: 'requested' });

    await expect(
      controller.confirmEmailVerification({
        email: EMAIL,
        code: CODE,
      }),
    ).resolves.toEqual({ message: 'confirmed' });

    expect(emailVerification.requestCode)
      .toHaveBeenCalledWith(EMAIL);

    expect(emailVerification.confirmCode)
      .toHaveBeenCalledWith(EMAIL, CODE);
  });
});

describe('Session controller route coverage', () => {
  it('delegates refresh', async () => {
    const sessions = {
      refresh: vi.fn().mockResolvedValue({
        accessToken: 'token',
      }),
    };

    const controller = new AuthSessionController(
      sessions as never,
    );

    await expect(
      controller.refresh({ refreshToken: TOKEN }),
    ).resolves.toEqual({ accessToken: 'token' });

    expect(sessions.refresh).toHaveBeenCalledWith(TOKEN);
  });

  it('revokes the current session', async () => {
    const sessions = {
      logoutCurrent: vi.fn().mockResolvedValue({
        message: 'Signed out.',
      }),
    };

    const controller = new AuthSessionController(
      sessions as never,
    );

    await expect(
      controller.logout({
        user: { id: UID },
        sessionId: SID,
      }),
    ).resolves.toEqual({ message: 'Signed out.' });

    expect(sessions.logoutCurrent)
      .toHaveBeenCalledWith(UID, SID);
  });

  it('revokes all sessions for the authenticated user', async () => {
    const sessions = {
      logoutAll: vi.fn().mockResolvedValue({
        message: 'All sessions revoked.',
      }),
    };

    const controller = new AuthSessionController(
      sessions as never,
    );

    await expect(
      controller.logoutAll({ user: { id: UID }, sessionId: SID }),
    ).resolves.toEqual({
      message: 'All sessions revoked.',
    });

    expect(sessions.logoutAll).toHaveBeenCalledWith(UID, SID);
  });
});

// ============================================
// SESSION TOKEN SECURITY COVERAGE
// ============================================

describe('Session service security coverage', () => {
  it('rejects malformed refresh tokens', async () => {
    const h = sessionHarness();

    await expect(
      h.service.refresh('not-a-token'),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.prisma.authSession.findUnique)
      .not.toHaveBeenCalled();
  });

  it('rejects malformed tokens during logout', async () => {
    const h = sessionHarness();

    await expect(
      h.service.logout('invalid-token'),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.prisma.authSession.updateMany)
      .not.toHaveBeenCalled();
  });

  it('rejects invalid stored hashes', async () => {
    const h = sessionHarness();

    h.prisma.authSession.findUnique.mockResolvedValue({
      ...validSession(),
      tokenHash: 'invalid-hash',
    });

    await expect(
      h.service.refresh(TOKEN),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('handles malformed token hashes safely', () => {
    const h = sessionHarness();

    const helper = h.service as unknown as {
      hashEquals(a: string, b: string): boolean;
    };

    expect(helper.hashEquals('bad', TOKEN_HASH)).toBe(false);
    expect(helper.hashEquals(TOKEN_HASH, 'bad')).toBe(false);
    expect(helper.hashEquals(TOKEN_HASH, TOKEN_HASH)).toBe(true);
  });

  it('does not claim a successful session when JWT signing fails inside transaction', async () => {
    const h = sessionHarness(); h.jwt.signAsync.mockRejectedValue(new Error('sign failed'));
    await expect(h.service.issue(UID, 3)).rejects.toThrow('sign failed');
    expect(h.prisma.$transaction).toHaveBeenCalledOnce();
    expect(h.tx.authSession.create).toHaveBeenCalledOnce();
    expect(h.tx.authSession.deleteMany).not.toHaveBeenCalled();
  });

  it.each([
    'missing',
    'revoked',
    'expired',
    'absolute-expired',
    'inactive',
    'wrong-version',
    'unverified',
  ])('rejects invalid session: %s', async (scenario) => {
    const h = sessionHarness();
    const session = validSession();

    if (scenario === 'missing') {
      h.prisma.authSession.findUnique.mockResolvedValue(null);
    } else {
      if (scenario === 'revoked') {
        session.revokedAt = new Date();
      }

      if (scenario === 'expired') {
        session.expiresAt = new Date(Date.now() - 1000);
      }

      if (scenario === 'absolute-expired') {
        session.absoluteExpiresAt = new Date(
          Date.now() - 1000,
        );
      }

      if (scenario === 'inactive') {
        session.user.isActive = false;
      }

      if (scenario === 'wrong-version') {
        session.user.sessionVersion = 4;
      }

      if (scenario === 'unverified') {
        session.user.passwordHash = 'hashed-password';
        session.user.emailVerifiedAt = null;
      }

      h.prisma.authSession.findUnique.mockResolvedValue(session);
    }

    await expect(
      h.service.refresh(TOKEN),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();
    expect(h.tx.usedRefreshToken.create).not.toHaveBeenCalled();
  });

  it('rotates token for verified password accounts', async () => {
    const h = sessionHarness();

    h.prisma.authSession.findUnique.mockResolvedValue({
      ...validSession(),
      user: {
        ...validSession().user,
        passwordHash: 'hash',
      },
    });

    await expect(
      h.service.refresh(TOKEN),
    ).resolves.toHaveProperty('refreshToken');
  });

  it.each([
    'no-used-token',
    'different-session',
    'recent',
    'future',
    'used-without-date',
    'aged',
  ])('handles replay record: %s', async (scenario) => {
    const h = sessionHarness();

    h.prisma.authSession.findUnique.mockResolvedValue({
      ...validSession(),
      tokenHash: 'b'.repeat(64),
    });

    const used = scenario === 'no-used-token'
      ? null
      : {
          sessionId:
            scenario === 'different-session'
              ? UID
              : SID,
          usedAt:
            scenario === 'used-without-date'
              ? null
              : new Date(
                  Date.now() +
                    (scenario === 'future'
                      ? 60000
                      : scenario === 'aged'
                        ? -60000
                        : 0),
                ),
        };

    h.prisma.usedRefreshToken.findUnique
      .mockResolvedValue(used);

    await expect(
      h.service.refresh(TOKEN),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    const revoked = [
      'future',
      'used-without-date',
      'aged',
    ].includes(scenario);

    expect(h.prisma.authSession.updateMany)
      .toHaveBeenCalledTimes(revoked ? 1 : 0);
  });

  it('rejects concurrent token rotation conflicts', async () => {
    const h = sessionHarness();

    h.tx.authSession.updateMany.mockResolvedValue({
      count: 0,
    });

    await expect(
      h.service.refresh(TOKEN),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.usedRefreshToken.create)
      .not.toHaveBeenCalled();

    expect(h.prisma.usedRefreshToken.findUnique)
      .not.toHaveBeenCalled();
  });

  it('rejects unexpected transaction failures', async () => {
    const h = sessionHarness();

    h.tx.usedRefreshToken.create.mockRejectedValue(
      new Error('DB rejected'),
    );

    await expect(
      h.service.refresh(TOKEN),
    ).rejects.toThrow('DB rejected');

    expect(h.prisma.usedRefreshToken.findUnique)
      .not.toHaveBeenCalled();
  });

  it('limits rolling refresh expiry to seven days', async () => {
    const h = sessionHarness();

    h.prisma.authSession.findUnique.mockResolvedValue({
      ...validSession(),
      absoluteExpiresAt: new Date(
        Date.now() + 30 * DAY,
      ),
    });

    await h.service.refresh(TOKEN);

    const call =
      h.tx.authSession.updateMany.mock.calls[0][0];

    const renewed: Date = call.data.expiresAt;
    const remaining = renewed.getTime() - Date.now();

    expect(remaining).toBeGreaterThan(6 * DAY);
    expect(remaining).toBeLessThanOrEqual(7 * DAY);
  });
});

// ============================================
// EMAIL VERIFICATION COVERAGE
// ============================================

describe('Email verification send coverage', () => {
  it.each([
    'no-key',
    'no-sender',
  ])('rejects missing email configuration: %s', async (scenario) => {
    const h = emailHarness();

    h.config.get.mockImplementation((name: string) => {
      if (
        scenario === 'no-key' &&
        name === 'RESEND_API_KEY'
      ) return undefined;

      if (
        scenario === 'no-sender' &&
        name === 'RESET_EMAIL_FROM'
      ) return undefined;

      return 'test-value';
    });

    await expect(
      h.service.requestCode(EMAIL),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(h.prisma.user.findUnique)
      .not.toHaveBeenCalled();
  });

  it.each([
    'missing',
    'inactive',
    'without-password',
    'verified',
  ])('does not send for ineligible user: %s', async (scenario) => {
    const h = emailHarness();
    const user = validUser();

    if (scenario === 'missing') {
      h.prisma.user.findUnique.mockResolvedValue(null);
    } else {
      if (scenario === 'inactive') {
        user.isActive = false;
      }

      if (scenario === 'without-password') {
        user.passwordHash = null;
      }

      if (scenario === 'verified') {
        user.emailVerifiedAt = new Date();
      }

      h.prisma.user.findUnique.mockResolvedValue(user);
    }

    const result = await h.service.requestCode(
      ' TEST@EXAMPLE.COM ',
    );

    expect(result.message).toContain('code');

    expect(h.tx.emailVerificationCode.upsert).not.toHaveBeenCalled();
  });

  it('does not send when the quota blocks the request', async () => {
    const h = emailHarness();

    h.tx.emailVerificationCode.findUnique.mockResolvedValue({ ...validRecord(), sentAt: new Date(Date.now()-120000), windowStartedAt: new Date(Date.now()-120000), sentInWindow: 5 });

    const send = vi.fn();
    vi.stubGlobal('fetch', send);

    await expect(
      h.service.requestCode(EMAIL),
    ).resolves.toHaveProperty('message');

    expect(send).not.toHaveBeenCalled();
  });

  it('sends an eight-digit code to normalized email', async () => {
    const h = emailHarness();

    const send = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
    });

    vi.stubGlobal('fetch', send);

    await expect(
      h.service.requestCode(' TEST@EXAMPLE.COM '),
    ).resolves.toHaveProperty('message');

    expect(send).toHaveBeenCalledOnce();

    expect(send.mock.calls[0][0])
      .toBe('https://api.resend.com/emails');

    const body = JSON.parse(
      send.mock.calls[0][1].body as string,
    );

    expect(body.to).toEqual([EMAIL]);
    expect(body.text).toMatch(/\b\d{8}\b/);
    expect(body.text).toContain('10 minutes');
  });

  it('handles a rejected email HTTP response', async () => {
    const h = emailHarness();

    const send = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
    });

    vi.stubGlobal('fetch', send);

    await expect(
      h.service.requestCode(EMAIL),
    ).resolves.toHaveProperty('message');

    expect(send).toHaveBeenCalledOnce();
  });

  it.each([
    'error',
    'non-error',
  ])('handles mail transport failures: %s', async (scenario) => {
    const h = emailHarness();

    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(
        scenario === 'error'
          ? new Error('offline')
          : 'network unavailable',
      ),
    );

    await expect(
      h.service.requestCode(EMAIL),
    ).resolves.toHaveProperty('message');
  });
});

describe('Email verification confirmation coverage', () => {
  it.each([
    'missing',
    'inactive',
    'no-password',
    'verified',
  ])('rejects ineligible user: %s', async (scenario) => {
    const h = emailHarness();
    const user = validUser();

    if (scenario === 'missing') {
      h.prisma.user.findUnique.mockResolvedValue(null);
    } else {
      if (scenario === 'inactive') {
        user.isActive = false;
      }

      if (scenario === 'no-password') {
        user.passwordHash = null;
      }

      if (scenario === 'verified') {
        user.emailVerifiedAt = new Date();
      }

      h.prisma.user.findUnique.mockResolvedValue(user);
    }

    await expect(
      h.service.confirmCode(EMAIL, CODE),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.prisma.emailVerificationCode.findUnique)
      .not.toHaveBeenCalled();
  });

  it.each([
    'missing',
    'expired',
    'attempts-exhausted',
  ])('rejects unusable code: %s', async (scenario) => {
    const h = emailHarness();

    if (scenario === 'missing') {
      h.prisma.emailVerificationCode.findUnique
        .mockResolvedValue(null);
    } else {
      const record = validRecord();

      if (scenario === 'expired') {
        record.expiresAt = new Date(
          Date.now() - 1000,
        );
      }

      if (scenario === 'attempts-exhausted') {
        record.attempts = 5;
      }

      h.prisma.emailVerificationCode.findUnique
        .mockResolvedValue(record);
    }

    await expect(
      h.service.confirmCode(EMAIL, CODE),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
    expect(h.tx.emailVerificationCode.updateMany).not.toHaveBeenCalled();
  });

  it.each([
    'malformed-stored-hash',
    'wrong-code',
  ])('counts failed code attempts: %s', async (scenario) => {
    const h = emailHarness();

    h.prisma.emailVerificationCode.findUnique
      .mockResolvedValue({
        ...validRecord(),
        codeHash:
          scenario === 'malformed-stored-hash'
            ? 'ab'
            : 'b'.repeat(64),
      });

    await expect(
      h.service.confirmCode(EMAIL, CODE),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.prisma.emailVerificationCode.updateMany)
      .toHaveBeenCalledWith(
        expect.objectContaining({
          data: {
            attempts: { increment: 1 },
          },
        }),
      );
  });

  it('rejects a concurrently consumed code', async () => {
    const h = emailHarness();

    h.tx.emailVerificationCode.updateMany
      .mockResolvedValue({ count: 0 });

    await expect(
      h.service.confirmCode(EMAIL, CODE),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.updateMany)
      .not.toHaveBeenCalled();
  });

  it('rejects a concurrent user verification update', async () => {
    const h = emailHarness();

    h.tx.user.updateMany.mockResolvedValue({
      count: 0,
    });

    await expect(
      h.service.confirmCode(EMAIL, CODE),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.emailVerificationCode.updateMany)
      .toHaveBeenCalledOnce();
  });

  it('verifies valid code and consumes it', async () => {
    const h = emailHarness();

    await expect(
      h.service.confirmCode(EMAIL, CODE),
    ).resolves.toHaveProperty(
      'message',
      'Email verified. You can now sign in.',
    );

    expect(h.tx.emailVerificationCode.updateMany)
      .toHaveBeenCalledOnce();

    expect(h.tx.user.updateMany)
      .toHaveBeenCalledOnce();
  });
});

// ============================================
// JWT AUTH GUARD COVERAGE
// ============================================

function guardHarness() {
  const request: {
    headers: { authorization: string };
    user?: unknown;
    sessionId?: string;
  } = {
    headers: {
      authorization: 'Bearer access-token',
    },
  };

  const prisma = {
    authSession: {
      findUnique: vi.fn().mockResolvedValue({
        userId: UID,
        sessionVersion: 3,
        revokedAt: null,
        expiresAt: new Date(Date.now() + 60000), absoluteExpiresAt: new Date(Date.now() + 120000), lastActiveAt: new Date(),
      }),
    },
    user: {
      findUnique: vi.fn().mockResolvedValue({
        id: UID,
        isActive: true,
        sessionVersion: 3,
        passwordHash: null,
        emailVerifiedAt: null,
        email: EMAIL,
      }),
    },
  };

  const jwt = {
    verifyAsync: vi.fn().mockResolvedValue({
      sub: UID,
      sid: SID,
      purpose: 'access',
      sv: 3, exp: Math.floor(Date.now() / 1000) + 600,
    }),
  };

  const guard = new JwtAuthGuard(
    jwt as never,
    prisma as never,
  );

  const context = {
    switchToHttp: () => ({
      getRequest: () => request,
    }),
  } as unknown as ExecutionContext;

  return { guard, jwt, prisma, request, context };
}

describe('JWT Guard remaining coverage', () => {
  it.each([
    'missing',
    'not-a-uuid',
  ])('rejects invalid JWT subject: %s', async (scenario) => {
    const h = guardHarness();

    h.jwt.verifyAsync.mockResolvedValue({
      sub:
        scenario === 'missing'
          ? undefined
          : 'not-a-uuid',
      sid: SID,
      purpose: 'access',
      sv: 3,
    });

    await expect(
      h.guard.canActivate(h.context),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.prisma.authSession.findUnique)
      .not.toHaveBeenCalled();
  });

  it('rejects an unverified password account', async () => {
    const h = guardHarness();

    h.prisma.user.findUnique.mockResolvedValue({
      id: UID,
      isActive: true,
      sessionVersion: 3,
      passwordHash: 'hash',
      emailVerifiedAt: null,
    });

    await expect(
      h.guard.canActivate(h.context),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.request.user).toBeUndefined();
  });

  it('allows verified accounts and removes sensitive fields', async () => {
    const h = guardHarness();

    h.prisma.user.findUnique.mockResolvedValue({
      id: UID,
      isActive: true,
      sessionVersion: 3,
      passwordHash: 'hash',
      emailVerifiedAt: new Date(),
      email: EMAIL,
    });

    await expect(
      h.guard.canActivate(h.context),
    ).resolves.toBe(true);

    expect(h.request.sessionId).toBe(SID);

    expect(h.request.user).toEqual({
      id: UID,
      email: EMAIL,
    });
  });
});

// Final coverage closeout

describe('Final verification and session boundaries', () => {
  it('does not send another verification email during cooldown', async () => {
    const h = emailHarness();
    h.tx.emailVerificationCode.findUnique.mockResolvedValue({
      ...validRecord(),
      sentAt: new Date()
    });

    const send = vi.fn();
    vi.stubGlobal('fetch', send);

    await expect(h.service.requestCode(EMAIL))
      .resolves.toHaveProperty('message');

    expect(h.tx.emailVerificationCode.upsert).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
  });

  it.each(['', '1234567', 'abcdefgh'])(
    'rejects malformed verification code %s',
    async code => {
      const h = emailHarness();

      await expect(h.service.confirmCode(EMAIL, code))
        .rejects.toBeInstanceOf(BadRequestException);

      expect(h.prisma.user.findUnique).not.toHaveBeenCalled();
    }
  );

  it('does not emit another replay audit when the session is already revoked', async () => {
    const h = sessionHarness();

    h.tx.authSession.findFirst.mockResolvedValue({
      ...validSession(),
      tokenHash: 'b'.repeat(64)
    });

    h.tx.usedRefreshToken.findUnique.mockResolvedValue({
      sessionId: SID,
      usedAt: new Date(Date.now() - 30000)
    });

    h.tx.authSession.updateMany.mockResolvedValue({ count: 0 });

    await expect(h.service.refresh(TOKEN))
      .rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.securityEvent.create).not.toHaveBeenCalled();
    expect(h.tx.usedRefreshToken.create).not.toHaveBeenCalled();
  });
});
