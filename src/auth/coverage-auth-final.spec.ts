import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  BadRequestException, ConflictException, UnauthorizedException,
} from '@nestjs/common';
import { compare, hash } from 'bcryptjs';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';

const UID = '11111111-1111-4111-8111-111111111111';
const SID = '22222222-2222-4222-8222-222222222222';
const OLD = 'ExistingPassword123!';
const NEXT = 'CompletelyNewPassword456!';
let oldHash: string;

beforeAll(async () => {
  oldHash = await hash(OLD, 4);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function harness() {
  const user = { id: UID, email: 'patient@example.com', isActive: true,
    passwordHash: oldHash, emailVerifiedAt: new Date(), sessionVersion: 3,
    preferredLanguage: 'en' };
  const tx = {
    $queryRaw: vi.fn().mockResolvedValue([]),
    user: { findFirst: vi.fn().mockResolvedValue({ id: UID }),
      findUnique: vi.fn().mockResolvedValue(user), updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    authSession: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    passwordResetCode: { deleteMany: vi.fn().mockResolvedValue({ count: 1 }) },
    emailVerificationCode: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    emailChangeRequest: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    googleActionChallenge: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    securityEvent: { create: vi.fn().mockResolvedValue({}) },
    securityNotification: { create: vi.fn().mockResolvedValue({}) },
  };
  const prisma = {
    user: { findUnique: vi.fn().mockResolvedValue(user) },
    $transaction: vi.fn(async (callback: (client: typeof tx) => Promise<unknown>) => callback(tx)),
  };
  const mfa = { verifySensitiveActionInTransaction: vi.fn().mockResolvedValue(true) };
  const service = new AuthService(prisma as never, {} as never, mfa as never);
  return { service, prisma, tx, mfa, user };
}

describe('Change password: all observable success and failure paths', () => {
  it.each([
    ['too short', 'short'],
    ['more than 72 UTF-8 bytes', '界'.repeat(25)],
  ])('rejects a %s new password before querying the user', async (_label, newPassword) => {
    const h = harness();
    await expect(h.service.changePassword(UID, OLD, newPassword, SID))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.user.findUnique).not.toHaveBeenCalled();
  });

  it('rejects an account that no longer exists', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue(null);
    await expect(h.service.changePassword(UID, OLD, NEXT, SID))
      .rejects.toBeInstanceOf(UnauthorizedException);
    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('rejects a disabled account', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ ...h.user, isActive: false });
    await expect(h.service.changePassword(UID, OLD, NEXT, SID))
      .rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects an OAuth-only account without a password', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ ...h.user, passwordHash: null });
    await expect(h.service.changePassword(UID, OLD, NEXT, SID))
      .rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects the wrong current password', async () => {
    const h = harness();
    await expect(h.service.changePassword(UID, 'WrongPassword123!', NEXT, SID))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('rejects password reuse even if the caller knows the current password', async () => {
    const h = harness();
    await expect(h.service.changePassword(UID, OLD, OLD, SID))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('refuses a stale concurrent account update', async () => {
    const h = harness();
    h.tx.user.updateMany.mockResolvedValue({ count: 0 });
    await expect(h.service.changePassword(UID, OLD, NEXT, SID))
      .rejects.toBeInstanceOf(ConflictException);
    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();
  });

  it('propagates session revocation errors instead of claiming success', async () => {
    const h = harness();
    h.tx.authSession.updateMany.mockRejectedValue(new Error('transaction aborted'));
    await expect(h.service.changePassword(UID, OLD, NEXT, SID))
      .rejects.toThrow('transaction aborted');
  });

  it('hashes the new password and revokes existing sessions in one transaction', async () => {
    const h = harness();
    const result = await h.service.changePassword(UID, OLD, NEXT, SID);
    expect(result.message).toContain('sessions have been revoked');
    expect(h.prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(h.tx.user.updateMany).toHaveBeenCalledWith({
      where: { id: UID, email: h.user.email, passwordHash: oldHash, isActive: true, sessionVersion: 3, emailVerifiedAt: { not: null } },
      data: {
        passwordHash: expect.any(String),
        sessionVersion: { increment: 1 },
      },
    });
    const saved = h.tx.user.updateMany.mock.calls[0][0].data.passwordHash as string;
    expect(saved).not.toBe(oldHash);
    expect(await compare(NEXT, saved)).toBe(true);
    expect(h.mfa.verifySensitiveActionInTransaction).toHaveBeenCalledWith(h.tx, UID, SID, 3, undefined);
    expect(h.tx.authSession.updateMany).toHaveBeenCalledTimes(2);
    expect(h.tx.authSession.updateMany).toHaveBeenCalledWith({
      where: { userId: UID, revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
  });

  it('does not change a password without verified email', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ ...h.user, emailVerifiedAt: null });
    await expect(h.service.changePassword(UID, OLD, NEXT, SID)).rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('commits failed MFA without changing credentials', async () => {
    const h = harness();
    h.mfa.verifySensitiveActionInTransaction.mockResolvedValue(false);
    await expect(h.service.changePassword(UID, OLD, NEXT, SID, '123456')).rejects.toBeInstanceOf(BadRequestException);
    expect(h.mfa.verifySensitiveActionInTransaction).toHaveBeenCalledWith(h.tx, UID, SID, 3, '123456');
    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
    expect(h.tx.securityNotification.create).not.toHaveBeenCalled();
  });

  it('queues verified-recipient notification instead of sending inside transaction', async () => {
    const h = harness();
    const send = vi.fn(); vi.stubGlobal('fetch', send);
    await h.service.changePassword(UID, OLD, NEXT, SID);
    expect(send).not.toHaveBeenCalled();
    expect(h.tx.securityNotification.create).toHaveBeenCalledWith({ data: { userId: UID, recipient: h.user.email, kind: 'PASSWORD_CHANGED', language: 'en' } });
    expect(h.tx.passwordResetCode.deleteMany).toHaveBeenCalledWith({ where: { userId: UID } });
    expect(h.tx.emailVerificationCode.updateMany).toHaveBeenCalledWith({ where: { userId: UID }, data: { attempts: 5 } });
    expect(h.tx.emailChangeRequest.updateMany).toHaveBeenCalledWith({ where: { userId: UID }, data: { attempts: 5 } });
    expect(h.tx.googleActionChallenge.updateMany).toHaveBeenCalledWith({ where: { userId: UID, consumedAt: null }, data: { consumedAt: expect.any(Date) } });
  });

  it('rejects an expired requesting session', async () => {
    const h = harness(); h.tx.authSession.updateMany.mockResolvedValueOnce({ count: 0 });
    await expect(h.service.changePassword(UID, OLD, NEXT, SID)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(h.tx.securityNotification.create).not.toHaveBeenCalled();
  });

  it('propagates outbox failure rather than claiming committed change', async () => {
    const h = harness(); h.tx.securityNotification.create.mockRejectedValue(new Error('outbox unavailable'));
    await expect(h.service.changePassword(UID, OLD, NEXT, SID)).rejects.toThrow('outbox unavailable');
    expect(h.tx.authSession.updateMany).toHaveBeenCalledTimes(2);
  });
});

describe('AuthController change-password route', () => {
  it('delegates the signed-in user ID and both password fields', async () => {
    const auth = {
      changePassword: vi.fn().mockResolvedValue({ message: 'done' }),
    };
    const controller = new AuthController(
      auth as never, {} as never, {} as never, {} as never,
    );
    await expect(controller.changePassword(
      { user: { id: UID }, sessionId: SID },
      { currentPassword: OLD, newPassword: NEXT },
    )).resolves.toEqual({ message: 'done' });
    expect(auth.changePassword).toHaveBeenCalledWith(UID, OLD, NEXT, SID, undefined);
  });
});

// Final coverage closeout

describe('Password change final transaction boundary', () => {
  it('rejects an account changed before acquiring the transaction lock', async () => {
    const h = harness();
    h.tx.user.findFirst.mockResolvedValue(null);

    await expect(
      h.service.changePassword(UID, OLD, NEXT, SID)
    ).rejects.toThrow('Account changed');

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();
    expect(h.tx.securityNotification.create).not.toHaveBeenCalled();
  });
});
