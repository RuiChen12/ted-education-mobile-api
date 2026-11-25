import {
  describe,
  expect,
  it,
  vi,
} from 'vitest';

import {
  UnauthorizedException,
} from '@nestjs/common';

import { createHmac } from 'node:crypto';
import { AuthSessionService } from './sessions/auth-session.service';
import { EmailVerificationService } from './email/email-verification.service';

const sid =
  '11111111-1111-4111-8111-111111111111';

const uid =
  '22222222-2222-4222-8222-222222222222';

const secret = 'harden-test-secret';
const token = sid + '.' + 'A'.repeat(43);

const digest = createHmac('sha256', secret)
  .update('ted:refresh:' + token)
  .digest('hex');

function harness(usedAt: Date) {
  const user = {
    id: uid,
    isActive: true,
    passwordHash: null,
    emailVerifiedAt: null,
    sessionVersion: 1,
  };

  const session = {
    id: sid,
    userId: uid,
    tokenHash: 'b'.repeat(64),
    revokedAt: null,
    expiresAt: new Date(Date.now() + 600000),
    absoluteExpiresAt: new Date(Date.now() + 600000),
    sessionVersion: 1,
    user,
  };

  const tx = {
    $queryRaw: vi.fn().mockResolvedValue([]),

    user: {
      findUnique: vi.fn().mockResolvedValue(user),
    },

    authSession: {
      findUnique: vi.fn().mockResolvedValue(session),
      findFirst: vi.fn().mockResolvedValue(session),
      updateMany: vi.fn().mockResolvedValue({
        count: 1,
      }),
    },

    usedRefreshToken: {
      findUnique: vi.fn().mockResolvedValue({
        sessionId: sid,
        usedAt,
      }),
    },

    securityEvent: {
      create: vi.fn().mockResolvedValue({}),
    },
  };

  const prisma = {
    ...tx,
    $transaction: vi.fn(
      async (fn: (client: typeof tx) => Promise<unknown>) =>
        fn(tx),
    ),
  };

  const service = new AuthSessionService(
    prisma as never,
    {} as never,
    {
      getOrThrow: () => secret,
    } as never,
  );

  return { prisma, service };
}

describe('Authentication hardening', () => {
  it('rejects recent duplicate refresh without revocation', async () => {
    const { prisma, service } = harness(new Date());

    await expect(
      service.refresh(token),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(
      prisma.authSession.updateMany,
    ).not.toHaveBeenCalled();
  });

  it('revokes a session after older token replay', async () => {
    const { prisma, service } = harness(
      new Date(Date.now() - 30000),
    );

    await expect(
      service.refresh(token),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(
      prisma.authSession.updateMany,
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: sid,
          userId: uid,
          revokedAt: null,
        },
      }),
    );
  });

  it('revokes by user and session id', async () => {
    const { prisma, service } = harness(new Date());

    await service.logoutCurrent(uid, sid);

    expect(
      prisma.authSession.updateMany,
    ).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: sid,
          userId: uid,
          revokedAt: null,
        },
      }),
    );

    expect(digest).toHaveLength(64);
  });

  it('reserves email quota atomically', async () => {
    const user = {
      id: uid,
      email: 'test@example.com',
      isActive: true,
      passwordHash: 'hash',
      emailVerifiedAt: null,
      sessionVersion: 1,
    };

    const tx = {
      $queryRaw: vi.fn().mockResolvedValue([]),

      user: {
        findUnique: vi.fn().mockResolvedValue(user),
      },

      emailVerificationCode: {
        findUnique: vi.fn().mockResolvedValue(null),
        upsert: vi.fn().mockResolvedValue({}),
      },
    };

    const prisma = {
      ...tx,
      $transaction: vi.fn(
        async (fn: (client: typeof tx) => Promise<unknown>) =>
          fn(tx),
      ),
    };

    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response('{}', { status: 200 }));

    try {
      const service = new EmailVerificationService(
        prisma as never,
        {
          get: (key: string) =>
            key === 'RESEND_API_KEY'
              ? 'test-key'
              : 'from@example.test',
          getOrThrow: () => secret,
        } as never,
      );

      const result = await service.requestCode(
        ' TEST@example.com ',
      );

      expect(result.message).toContain('code');

      expect(prisma.$transaction).toHaveBeenCalledOnce();
      expect(tx.$queryRaw).toHaveBeenCalledOnce();

      expect(tx.user.findUnique).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { email: 'test@example.com' },
        }),
      );

      expect(tx.emailVerificationCode.upsert)
        .toHaveBeenCalledWith(
          expect.objectContaining({
            where: { userId: uid },
            create: expect.objectContaining({
              userId: uid,
              attempts: 0,
              sentInWindow: 1,
              codeHash: expect.stringMatching(/^[a-f0-9]{64}$/),
            }),
          }),
        );

      expect(fetchMock).toHaveBeenCalledOnce();

      expect(
        tx.emailVerificationCode.upsert.mock.invocationCallOrder[0]
      ).toBeLessThan(fetchMock.mock.invocationCallOrder[0]);

    } finally {
      fetchMock.mockRestore();
    }
  });
});
