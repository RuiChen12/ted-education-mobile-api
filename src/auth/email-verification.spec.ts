import { describe, expect, it, vi } from 'vitest';
import {
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { createHmac } from 'node:crypto';
import { hash } from 'bcryptjs';

import { AuthService } from './auth.service';
import { EmailVerificationService } from './email/email-verification.service';

const ID = '11111111-1111-4111-8111-111111111111';
const SECRET = 'test-only-secret';

describe('Email verification', () => {
  it('blocks unverified password login', async () => {
    const prisma = {
      user: {
        findUnique: vi.fn().mockResolvedValue({
          id: ID,
          isActive: true,
          emailVerifiedAt: null,
          passwordHash: await hash('CorrectPassword123!', 4),
        }),
      },
    };

    const mfa = { loginResult: vi.fn() };

    const service = new AuthService(
      prisma as never,
      {} as never,
      mfa as never,
    );

    await expect(
      service.login({
        email: 'a@example.com',
        password: 'CorrectPassword123!',
      })
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(mfa.loginResult).not.toHaveBeenCalled();
  });

  function verificationHarness(expiresAt: Date) {
    const email = 'a@example.com';
    const code = '12345678';
    const version = 3;
    const sentAt = new Date(Date.now() - 60000);

    const codeHash = createHmac('sha256', SECRET)
      .update(JSON.stringify([
        'ted:verify-email:v2',
        ID,
        email,
        version,
        sentAt.toISOString(),
        code,
      ]))
      .digest('hex');

    const user = {
      id: ID,
      email,
      isActive: true,
      passwordHash: 'hash',
      emailVerifiedAt: null,
      sessionVersion: version,
    };

    const tx = {
      $queryRaw: vi.fn().mockResolvedValue([]),

      user: {
        findUnique: vi.fn().mockResolvedValue(user),
        updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      },

      emailVerificationCode: {
        findUnique: vi.fn().mockResolvedValue({
          userId: ID,
          codeHash,
          sentAt,
          attempts: 0,
          expiresAt,
        }),

        updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      },
    };

    const prisma = {
      ...tx,
      $transaction: vi.fn(
        async (fn: (client: typeof tx) => Promise<unknown>) =>
          fn(tx),
      ),
    };

    const service = new EmailVerificationService(
      prisma as never,
      { getOrThrow: () => SECRET } as never,
    );

    return { service, prisma, tx, email, code, codeHash };
  }

  it('rejects expired code', async () => {
    const { service, tx, email, code } =
      verificationHarness(new Date(Date.now() - 1000));

    await expect(
      service.confirmCode(email, code),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(tx.user.updateMany).not.toHaveBeenCalled();
    expect(tx.emailVerificationCode.updateMany)
      .not.toHaveBeenCalled();
  });

  it('consumes valid code in a transaction', async () => {
    const { service, prisma, tx, email, code, codeHash } =
      verificationHarness(new Date(Date.now() + 600000));

    const result = await service.confirmCode(email, code);

    expect(result.message).toContain('verified');
    expect(prisma.$transaction).toHaveBeenCalledOnce();
    expect(tx.$queryRaw).toHaveBeenCalledOnce();

    expect(tx.emailVerificationCode.updateMany)
      .toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            userId: ID,
            codeHash,
          }),
          data: {
            attempts: 5,
            expiresAt: expect.any(Date),
          },
        }),
      );

    expect(tx.user.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: ID,
          email,
          sessionVersion: 3,
          emailVerifiedAt: null,
        }),
        data: {
          emailVerifiedAt: expect.any(Date),
        },
      }),
    );
  });

  it('records a wrong code without verifying the account', async () => {
    const { service, tx, email } =
      verificationHarness(new Date(Date.now() + 600000));

    await expect(
      service.confirmCode(email, '87654321'),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(tx.emailVerificationCode.updateMany)
      .toHaveBeenCalledWith(
        expect.objectContaining({
          data: {
            attempts: { increment: 1 },
          },
        }),
      );

    expect(tx.user.updateMany).not.toHaveBeenCalled();
  });
});
