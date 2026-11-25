import { describe, expect, it, vi } from 'vitest';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { MfaService } from './mfa/mfa.service';
import { MfaController } from './mfa/mfa.controller';

const UID = '11111111-1111-4111-8111-111111111111';

const SID = '22222222-2222-4222-8222-222222222222';
function harness() {
  const tx = {
    $queryRaw: vi.fn().mockResolvedValue([]),
    user: { findUnique: vi.fn().mockResolvedValue({ id: UID, email: 'patient@example.com', isActive: true, passwordHash: null, emailVerifiedAt: new Date(), sessionVersion: 3, preferredLanguage: 'en' }) },
    authSession: { findFirst: vi.fn().mockResolvedValue({ id: SID }) },
    mfaSetting: { update: vi.fn().mockResolvedValue({}) },
    securityEvent: { create: vi.fn().mockResolvedValue({}) },
    securityNotification: { create: vi.fn().mockResolvedValue({}) },
  };
  const prisma = { ...tx, $transaction: vi.fn(async (fn: (client: typeof tx) => Promise<unknown>) => fn(tx)) };
  const config = { getOrThrow: vi.fn().mockReturnValue('a'.repeat(64)) };
  const service = new MfaService(prisma as never, {} as never, config as never, {} as never);
  const auth = vi.spyOn(service as unknown as { consumeFactor(tx: unknown, id: string, code: string, allowRecovery: boolean): Promise<boolean> }, 'consumeFactor').mockResolvedValue(true);
  return { service, prisma, tx, auth };
}

describe('MFA recovery code regeneration', () => {
  it('rejects backup codes, malformed codes and non-6-digit TOTP strings', async () => {
    const h = harness();
    for (const invalid of ['AABBCCDD-11223344', '12345', '1234567', 'abc123']) {
      await expect(h.service.regenerateRecoveryCodes(UID, invalid, SID))
        .rejects.toBeInstanceOf(BadRequestException);
    }
    expect(h.auth).not.toHaveBeenCalled();
    expect(h.prisma.mfaSetting.update).not.toHaveBeenCalled();
  });

  it('does not regenerate if the supplied authenticator code is invalid or replayed', async () => {
    const h = harness();
    h.auth.mockResolvedValue(false);
    await expect(h.service.regenerateRecoveryCodes(UID, '123456', SID))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.mfaSetting.update).not.toHaveBeenCalled();
  });

  it('atomically replaces the old hashes and returns eight unique one-time codes', async () => {
    const h = harness();
    const result = await h.service.regenerateRecoveryCodes(UID, '123456', SID);
    expect(h.auth).toHaveBeenCalledWith(h.tx, UID, '123456', false);
    expect(result.recoveryCodes).toHaveLength(8);
    expect(new Set(result.recoveryCodes).size).toBe(8);
    for (const code of result.recoveryCodes) {
      expect(code).toMatch(/^[A-F0-9]{8}-[A-F0-9]{8}$/);
    }
    expect(result.recoveryCodesRemaining).toBe(8);
    const update = h.prisma.mfaSetting.update.mock.calls[0][0];
    expect(update.where).toEqual({ userId: UID });
    expect(update.data.recoveryHashes).toHaveLength(8);
    expect(update.data.recoveryHashes.every((x: string) => /^[a-f0-9]{64}$/.test(x)))
      .toBe(true);
    expect(update.data.recoveryHashes).not.toContain(result.recoveryCodes[0]);
  });

  it('rejects an expired requesting session before consuming a factor', async () => {
    const h = harness(); h.tx.authSession.findFirst.mockResolvedValue(null);
    await expect(h.service.regenerateRecoveryCodes(UID, '123456', SID)).rejects.toBeInstanceOf(UnauthorizedException);
    expect(h.auth).not.toHaveBeenCalled();
    expect(h.tx.mfaSetting.update).not.toHaveBeenCalled();
  });
});

describe('MfaController regeneration route', () => {
  it('passes user and TOTP code through unchanged', async () => {
    const mfa = { regenerateRecoveryCodes: vi.fn().mockResolvedValue({ recoveryCodes: [] }) };
    const controller = new MfaController(mfa as never);
    await expect(controller.regenerateRecoveryCodes(
      { user: { id: UID, email: 'patient@example.com' }, sessionId: SID },
      { code: '123456' },
    )).resolves.toEqual({ recoveryCodes: [] });
    expect(mfa.regenerateRecoveryCodes).toHaveBeenCalledWith(UID, '123456', SID);
  });
});
