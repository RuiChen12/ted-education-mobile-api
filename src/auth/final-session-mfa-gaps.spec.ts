
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  BadRequestException,
  UnauthorizedException,

} from '@nestjs/common';
import { hash } from 'bcryptjs';

import { AuthSessionService } from './sessions/auth-session.service';
import { MfaService } from './mfa/mfa.service';
import { JwtAuthGuard } from './jwt/jwt-auth.guard';
import { AuthService } from './auth.service';

const UID = '11111111-1111-4111-8111-111111111111';
const SID = '22222222-2222-4222-8222-222222222222';
const TARGET = '33333333-3333-4333-8333-333333333333';

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function fixture() {
  const now = new Date();

  const user = {
    id: UID,
    email: 'patient@example.test',
    isActive: true,
    passwordHash: null,
    emailVerifiedAt: null,
    preferredLanguage: 'en',
    sessionVersion: 4
  };

  const session = {
    id: SID,
    userId: UID,
    revokedAt: null,
    sessionVersion: 4,
    createdAt: now,
    updatedAt: now,
    expiresAt: new Date(Date.now() + 600000),
    absoluteExpiresAt: new Date(Date.now() + 300000),
    devicePlatform: null,
    lastActiveAt: null
  };

  const tx = {
    $queryRaw: vi.fn().mockResolvedValue([]),
    user: {
      findUnique: vi.fn().mockResolvedValue(user),
      findFirst: vi.fn().mockResolvedValue({ id: UID }),
      update: vi.fn().mockResolvedValue({ id: UID }),
      updateMany: vi.fn().mockResolvedValue({ count: 1 })
    },
    authSession: {
      findFirst: vi.fn().mockResolvedValue(session),
      findUnique: vi.fn().mockResolvedValue(session),
      findMany: vi.fn().mockResolvedValue([]),
      updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      create: vi.fn().mockResolvedValue({})
    },
    mfaSetting: {
      findUnique: vi.fn().mockResolvedValue(null)
    },
    securityEvent: {
      findFirst: vi.fn().mockResolvedValue(null),
      create: vi.fn().mockResolvedValue({}),
      findMany: vi.fn().mockResolvedValue([])
    }
  };

  const prisma = {
    ...tx,
    $transaction: vi.fn(async (
      fn: (client: typeof tx) => Promise<unknown>
    ) => fn(tx))
  };

  const jwt = {
    verifyAsync: vi.fn().mockResolvedValue({
      sub: UID,
      sid: SID,
      purpose: 'access',
      sv: 4,
      exp: Math.floor(Date.now() / 1000) + 600
    }),
    signAsync: vi.fn().mockResolvedValue('test-token')
  };

  const config = {
    getOrThrow: vi.fn().mockReturnValue('a'.repeat(64))
  };

  const sessions = new AuthSessionService(
    prisma as never, jwt as never, config as never
  );

  const mfa = new MfaService(
    prisma as never, jwt as never,
    config as never, sessions
  );

  const auth = new AuthService(
    prisma as never, jwt as never, mfa
  );

  const guard = new JwtAuthGuard(
    jwt as never, prisma as never
  );

  const request = {
    headers: {
      authorization: 'Bearer test-token',
      'x-ted-platform': 'android'
    }
  };

  const context = {
    switchToHttp: () => ({
      getRequest: () => request
    })
  };

  return {
    user, session, tx, prisma,
    jwt, sessions, mfa, auth,
    guard, request, context
  };
}

describe('Active device session contracts', () => {
  it('lists the current session first and enforces the 101-session cap', async () => {
    const h = fixture();

    h.tx.authSession.findMany.mockResolvedValue(
      Array.from({ length: 101 }, (_, index) => ({
        ...h.session,
        id: 'other-' + index
      }))
    );

    const result = await h.sessions.listSessions(UID, SID);

    expect(result.sessions).toHaveLength(101);
    expect(result.sessions[0].id).toBe(SID);
    expect(result.sessions[0].current).toBe(true);
    expect(result.sessions[0].expiresAt)
      .toEqual(h.session.absoluteExpiresAt);

    expect(result.hasMore).toBe(true);

    expect(h.tx.authSession.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        take: 101,
        where: expect.objectContaining({
          userId: UID,
          sessionVersion: 4,
          revokedAt: null,
          id: { not: SID }
        })
      })
    );
  });

  it('reports no further devices for a short list', async () => {
    const h = fixture();
    const result = await h.sessions.listSessions(UID, SID);

    expect(result.sessions).toHaveLength(1);
    expect(result.hasMore).toBe(false);
  });

  it('rejects inactive device-list owners', async () => {
    const h = fixture();
    h.tx.user.findUnique.mockResolvedValue(null);

    await expect(h.sessions.listSessions(UID, SID))
      .rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.authSession.findMany).not.toHaveBeenCalled();
  });

  it('rejects device-list access without the current session', async () => {
    const h = fixture();
    h.tx.authSession.findFirst.mockResolvedValue(null);

    await expect(h.sessions.listSessions(UID, SID))
      .rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('does not revoke the current session using the other-device endpoint', async () => {
    const h = fixture();

    await expect(h.sessions.revokeSession(UID, SID, SID))
      .rejects.toBeInstanceOf(BadRequestException);

    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it.each([0, 1])('revokes an owner-scoped session, count=%s', async count => {
    const h = fixture();

    h.tx.authSession.updateMany.mockResolvedValue({ count });

    await expect(h.sessions.revokeSession(UID, SID, TARGET))
      .resolves.toEqual({
        message: 'Session revocation processed.'
      });

    expect(h.tx.authSession.updateMany).toHaveBeenCalledWith({
      where: {
        id: TARGET,
        userId: UID,
        revokedAt: null
      },
      data: { revokedAt: expect.any(Date) }
    });

    expect(h.tx.securityEvent.create)
      .toHaveBeenCalledTimes(count);
  });

  it('does not revoke another device from a stale session', async () => {
    const h = fixture();
    h.tx.authSession.findFirst.mockResolvedValue(null);

    await expect(h.sessions.revokeSession(UID, SID, TARGET))
      .rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();
  });

  it.each([-1, 1.5, 2147483648])(
    'rejects invalid session version %s',
    async version => {
      const h = fixture();

      await expect(
        h.sessions.issueInTransaction(
          h.tx as never, UID, version
        )
      ).rejects.toBeInstanceOf(UnauthorizedException);

      expect(h.tx.authSession.create).not.toHaveBeenCalled();
    }
  );

  it('rejects a stale account version during session issuance', async () => {
    const h = fixture();

    await expect(
      h.sessions.issueInTransaction(h.tx as never, UID, 3)
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.authSession.create).not.toHaveBeenCalled();
  });

  it('does not return a next cursor for empty activity', async () => {
    const h = fixture();

    await expect(h.sessions.listSecurityActivity(UID))
      .resolves.toEqual({
        events: [],
        hasMore: false,
        nextCursor: null
      });
  });

  it('rejects a failed logout-all version update', async () => {
    const h = fixture();

    h.tx.user.updateMany.mockResolvedValue({ count: 0 });

    await expect(h.sessions.logoutAll(UID, SID))
      .rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();
  });
});

describe('Sensitive MFA authorization', () => {
  it('accepts a valid session when MFA is disabled', async () => {
    const h = fixture();

    await expect(
      h.mfa.verifySensitiveActionInTransaction(
        h.tx as never, UID, SID, 4
      )
    ).resolves.toBe(true);
  });

  it.each([-1, 1.5, 2147483648])(
    'rejects invalid MFA session version %s',
    async version => {
      const h = fixture();

      await expect(
        h.mfa.verifySensitiveActionInTransaction(
          h.tx as never, UID, SID, version
        )
      ).rejects.toBeInstanceOf(UnauthorizedException);
    }
  );

  it('rejects a changed MFA account version', async () => {
    const h = fixture();

    await expect(
      h.mfa.verifySensitiveActionInTransaction(
        h.tx as never, UID, SID, 3
      )
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects an invalid account identifier', async () => {
    const h = fixture();

    await expect(
      h.mfa.verifySensitiveActionInTransaction(
        h.tx as never, 'invalid', SID, 4
      )
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects an invalid session identifier', async () => {
    const h = fixture();

    await expect(
      h.mfa.verifySensitiveActionInTransaction(
        h.tx as never, UID, 'invalid', 4
      )
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it.each([undefined, '12345', 'abcdef'])(
    'requires a six-digit factor when MFA is enabled',
    async code => {
      const h = fixture();

      h.tx.mfaSetting.findUnique.mockResolvedValue({
        enabledAt: new Date()
      });

      await expect(
        h.mfa.verifySensitiveActionInTransaction(
          h.tx as never, UID, SID, 4, code
        )
      ).resolves.toBe(false);
    }
  );

  it.each([true, false])(
    'preserves the factor-consumption outcome: %s',
    async valid => {
      const h = fixture();

      h.tx.mfaSetting.findUnique.mockResolvedValue({
        enabledAt: new Date()
      });

      const consume = vi.spyOn(
        h.mfa as unknown as {
          consumeFactor(
            tx: unknown,
            id: string,
            code: string,
            recovery: boolean
          ): Promise<boolean>
        },
        'consumeFactor'
      ).mockResolvedValue(valid);

      await expect(
        h.mfa.verifySensitiveActionInTransaction(
          h.tx as never, UID, SID, 4, '123456'
        )
      ).resolves.toBe(valid);

      expect(consume).toHaveBeenCalledWith(
        h.tx, UID, '123456', false
      );
    }
  );

  it('supports the legacy authorization method with MFA disabled', async () => {
    const h = fixture();

    await expect(h.mfa.verifySensitiveAction(UID))
      .resolves.toBeUndefined();

    expect(h.prisma.$transaction).toHaveBeenCalledOnce();
  });

  it('rejects missing factor in the compatibility method', async () => {
    const h = fixture();

    h.tx.mfaSetting.findUnique.mockResolvedValue({
      enabledAt: new Date()
    });

    await expect(h.mfa.verifySensitiveAction(UID))
      .rejects.toBeInstanceOf(BadRequestException);
  });
});

describe('JWT session metadata and expiration', () => {
  it.each([undefined, 0, 1.5])(
    'rejects invalid expiry %s',
    async exp => {
      const h = fixture();

      h.jwt.verifyAsync.mockResolvedValue({
        sub: UID, sid: SID,
        purpose: 'access', sv: 4, exp
      });

      await expect(h.guard.canActivate(h.context as never))
        .rejects.toBeInstanceOf(UnauthorizedException);

      expect(h.tx.authSession.findUnique).not.toHaveBeenCalled();
    }
  );

  it('records platform and activity with owner-scoped CAS', async () => {
    const h = fixture();

    await expect(h.guard.canActivate(h.context as never))
      .resolves.toBe(true);

    expect(h.tx.authSession.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: SID,
          userId: UID,
          sessionVersion: 4,
          revokedAt: null
        }),
        data: {
          devicePlatform: 'android',
          lastActiveAt: expect.any(Date)
        }
      })
    );
  });

  it('never trusts an unknown client platform', async () => {
    const h = fixture();
    h.request.headers['x-ted-platform'] = 'unknown-platform';

    await expect(h.guard.canActivate(h.context as never))
      .resolves.toBe(true);

    expect(h.tx.authSession.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        data: { lastActiveAt: expect.any(Date) }
      })
    );
  });

  it('does not invalidate valid authentication for metadata failure', async () => {
    const h = fixture();

    h.tx.authSession.updateMany.mockRejectedValue(
      new Error('metadata unavailable')
    );

    await expect(h.guard.canActivate(h.context as never))
      .resolves.toBe(true);
  });

  it('rejects expiration during account lookup', async () => {
    vi.useFakeTimers();
    const h = fixture();

    h.tx.user.findUnique.mockImplementation(async () => {
      vi.setSystemTime(Date.now() + 400000);
      return h.user;
    });

    await expect(h.guard.canActivate(h.context as never))
      .rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects expiration during optional metadata update', async () => {
    vi.useFakeTimers();
    const h = fixture();

    h.tx.authSession.updateMany.mockImplementation(async () => {
      vi.setSystemTime(Date.now() + 400000);
      return { count: 1 };
    });

    await expect(h.guard.canActivate(h.context as never))
      .rejects.toBeInstanceOf(UnauthorizedException);
  });
});

describe('Authentication failure auditing and profile authorization', () => {
  it('records an unsuccessful password attempt', async () => {
    const h = fixture();

    h.tx.user.findUnique.mockResolvedValue({
      ...h.user,
      passwordHash: await hash('ValidPassword123!', 4)
    });

    await expect(h.auth.login({
      email: h.user.email,
      password: 'incorrect'
    })).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.securityEvent.create).toHaveBeenCalledWith({
      data: {
        userId: UID,
        type: 'PASSWORD_LOGIN_FAILED',
        createdAt: expect.any(Date)
      }
    });
  });

  it('keeps authentication denied when audit recording fails', async () => {
    const h = fixture();

    h.tx.user.findUnique.mockResolvedValue({
      ...h.user,
      passwordHash: await hash('ValidPassword123!', 4)
    });

    h.tx.securityEvent.create.mockRejectedValue(
      new Error('audit failed')
    );

    await expect(h.auth.login({
      email: h.user.email,
      password: 'incorrect'
    })).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects an empty current password before querying the account', async () => {
    const h = fixture();

    await expect(h.auth.changePassword(
      UID, '', 'NewPassword123!', SID
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.findUnique).not.toHaveBeenCalled();
  });

  it('rejects a disabled profile owner', async () => {
    const h = fixture();

    h.tx.user.findUnique.mockResolvedValue(null);

    await expect(h.auth.updateAccount(UID, {}, SID))
      .rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.user.update).not.toHaveBeenCalled();
  });

  it('rejects profile updates without verified password ownership', async () => {
    const h = fixture();

    h.tx.user.findUnique.mockResolvedValue({
      ...h.user,
      passwordHash: 'test-hash',
      emailVerifiedAt: null
    });

    await expect(h.auth.updateAccount(UID, {}, SID))
      .rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects profile updates from a revoked session', async () => {
    const h = fixture();

    h.tx.authSession.findFirst.mockResolvedValue(null);

    await expect(h.auth.updateAccount(UID, {}, SID))
      .rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.user.update).not.toHaveBeenCalled();
  });
});


describe('Final audit boundary tests', () => {
  it('does not record failed login against a changed account', async () => {
    const h = fixture();

    h.tx.user.findUnique.mockResolvedValue({
      ...h.user,
      passwordHash: await hash('ValidPassword123!', 4)
    });

    h.tx.user.findFirst.mockResolvedValue(null);

    await expect(h.auth.login({
      email: h.user.email,
      password: 'wrong-password'
    })).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.securityEvent.create).not.toHaveBeenCalled();
  });

  it('returns generic logout success for an absent session', async () => {
    const h = fixture();
    h.tx.authSession.findUnique.mockResolvedValue(null);

    await expect(h.sessions.logout(SID + '.' + 'A'.repeat(43)))
      .resolves.toEqual({ message: 'Signed out.' });

    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('does not audit a duplicate current-session logout', async () => {
    const h = fixture();
    h.tx.authSession.updateMany.mockResolvedValue({ count: 0 });

    await expect(h.sessions.logoutCurrent(UID, SID))
      .resolves.toEqual({ message: 'Signed out.' });

    expect(h.tx.securityEvent.create).not.toHaveBeenCalled();
  });
});
