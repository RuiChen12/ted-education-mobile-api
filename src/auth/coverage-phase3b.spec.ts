import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  BadRequestException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import { createHmac } from 'node:crypto';

import { MfaService } from './mfa/mfa.service';
import { MfaController } from './mfa/mfa.controller';
import { JwtAuthGuard } from './jwt/jwt-auth.guard';
import { enqueueSecurityNotification, SecurityNotificationService } from '../notifications/security-notification.service';

const ID = '11111111-1111-4111-8111-111111111111';
const EMAIL = 'patient@example.com';
const KEY = 'a'.repeat(64);
const SECRET = 'JBSWY3DPEHPK3PXP'.repeat(2);
const SID = '22222222-2222-4222-8222-222222222222';
const JTI = '33333333-3333-4333-8333-333333333333';
const RECOVERY = 'ABCDEF12-34567890';

function clock() {
  const instant =
    Math.floor(Date.now() / 30000) * 30000 + 15000;

  vi.useFakeTimers();
  vi.setSystemTime(instant);

  return instant;
}

function totp(secret: string, step: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;

  for (const ch of secret.toUpperCase()) {
    value = (value << 5) | alphabet.indexOf(ch);
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));

  const digest = createHmac('sha1', Buffer.from(bytes))
    .update(counter)
    .digest();

  const offset = digest[digest.length - 1] & 15;

  const value6 =
    (digest.readUInt32BE(offset) & 0x7fffffff) % 1000000;

  return String(value6).padStart(6, '0');
}

type InternalMfa = {
  encrypt(value: string): string;
  decrypt(value: string): string;
  recoveryHash(value: string): string;
};

function harness() {
  const user = { id: ID, email: EMAIL, isActive: true, sessionVersion: 7, passwordHash: null, emailVerifiedAt: new Date(), preferredLanguage: 'en' };
  const tx = {
    $queryRaw: vi.fn().mockResolvedValue([]),
    user: { findUnique: vi.fn().mockResolvedValue(user), updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    authSession: { findFirst: vi.fn().mockResolvedValue({ id: SID }), updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    mfaSetting: { findUnique: vi.fn().mockResolvedValue(null), upsert: vi.fn().mockResolvedValue({}), update: vi.fn().mockResolvedValue({}), updateMany: vi.fn().mockResolvedValue({ count: 1 }), deleteMany: vi.fn().mockResolvedValue({ count: 1 }) },
    mfaLoginChallenge: { findFirst: vi.fn().mockResolvedValue({ challengeId: JTI }), deleteMany: vi.fn().mockResolvedValue({ count: 1 }) },
    passwordResetCode: { deleteMany: vi.fn().mockResolvedValue({ count: 1 }) },
    emailChangeRequest: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    googleActionChallenge: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    securityEvent: { findFirst: vi.fn().mockResolvedValue(null), create: vi.fn().mockResolvedValue({}) },
    securityNotification: { create: vi.fn().mockResolvedValue({}) },
  };
  const prisma = { ...tx, $transaction: vi.fn(async (fn: (client: typeof tx) => Promise<unknown>) => fn(tx)) };
  const jwt = { signAsync: vi.fn().mockResolvedValue('access-token'), verifyAsync: vi.fn() };
  const config = { getOrThrow: vi.fn().mockReturnValue(KEY), get: vi.fn().mockReturnValue(undefined) };
  const sessions = { issueInTransaction: vi.fn().mockResolvedValue({ mfaRequired: false, accessToken: 'access-token', refreshToken: 'test-refresh-token', tokenType: 'Bearer', expiresIn: 900 }) };
  const service = new MfaService(prisma as never, jwt as never, config as never, sessions as never);
  const inside = service as unknown as InternalMfa;
  return { prisma, tx, jwt, config, service, inside, sessions };
}

function factor(h: ReturnType<typeof harness>) {
  return {
    userId: ID, enabledAt: new Date(),
    pendingAt: new Date(Date.now()),
    pendingCipher: h.inside.encrypt(JSON.stringify(['ted:mfa-setup:v2', ID, SID, 7, SECRET])),
    secretCipher: h.inside.encrypt(SECRET),
    lastUsedStep: -1,
    attempts: 0,
    lockedUntil: null as Date | null,
    recoveryHashes: [] as string[],
  };
}

function tx(h: ReturnType<typeof harness>, updateCount = 1, deleteCount = 1) {
  h.tx.mfaSetting.updateMany.mockResolvedValue({ count: updateCount });
  h.tx.mfaSetting.deleteMany.mockResolvedValue({ count: deleteCount });
  return h.tx;
}

function challenge(
  h: ReturnType<typeof harness>,
  f = factor(h),
) {
  h.jwt.verifyAsync.mockResolvedValue({
    sub: ID,
    purpose: 'mfa', jti: JTI, exp: Math.floor(Date.now() / 1000) + 600,
    sv: 7,
  });

  h.prisma.user.findUnique.mockResolvedValue({
    id: ID, email: EMAIL, emailVerifiedAt: new Date(), preferredLanguage: 'en', passwordHash: null, isActive: true,
    sessionVersion: 7,
  });

  h.prisma.mfaSetting.findUnique.mockResolvedValue(f);

  return f;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('MFA setup and encryption', () => {
  it('rejects an invalid encryption key', async () => {
    const h = harness();

    h.config.getOrThrow.mockReturnValue('invalid-key');

    await expect(
      h.service.setup(ID, SID),
    ).rejects.toThrow('64 hex characters');

    expect(h.prisma.mfaSetting.upsert)
      .not.toHaveBeenCalled();
  });

  it('encrypts a new authenticator secret', async () => {
    const h = harness();

    const result = await h.service.setup(ID, SID);

    const call =
      h.prisma.mfaSetting.upsert.mock.calls[0][0];

    expect(result.uri).toContain('otpauth://totp/');

    expect(result.uri).toContain(
      'secret=' + result.secret,
    );

    expect(call.create.pendingCipher)
      .not.toContain(result.secret);

    expect(
      h.inside.decrypt(call.create.pendingCipher),
    ).toBe(JSON.stringify(['ted:mfa-setup:v2', ID, SID, 7, result.secret]));

    expect(
      h.inside.decrypt(call.update.pendingCipher),
    ).toBe(JSON.stringify(['ted:mfa-setup:v2', ID, SID, 7, result.secret]));
  });

  it('rejects corrupted encrypted data', () => {
    const h = harness();

    expect(() => {
      h.inside.decrypt('invalid');
    }).toThrow('Invalid encrypted secret');

    const encrypted =
      h.inside.encrypt(SECRET).split('.');

    encrypted[2] =
      Buffer.from('altered').toString('base64url');

    expect(() => {
      h.inside.decrypt(encrypted.join('.'));
    }).toThrow();
  });

  it.each([
    ['missing factor', null],
    ['already enabled', {
      enabledAt: new Date(),
    }],
    ['no pending secret', {
      enabledAt: null,
      pendingCipher: null,
      pendingAt: new Date(),
    }],
    ['no pending date', {
      enabledAt: null,
      pendingCipher: 'cipher',
      pendingAt: null,
    }],
    ['expired setup', {
      enabledAt: null,
      pendingCipher: 'cipher',
      pendingAt: new Date(0),
    }],
  ])('rejects enable when %s', async (_name, data) => {
    const h = harness();

    h.prisma.mfaSetting.findUnique
      .mockResolvedValue(data);

    await expect(
      h.service.enable(ID, '123456', SID),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects an incorrect setup code', async () => {
    const h = harness();

    h.prisma.mfaSetting.findUnique
      .mockResolvedValue({ ...factor(h), enabledAt: null });

    await expect(
      h.service.enable(ID, 'invalid', SID),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.mfaSetting.updateMany).not.toHaveBeenCalled();
    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('enables MFA and generates eight recovery codes', async () => {
    const at = clock();
    const h = harness();

    h.prisma.mfaSetting.findUnique
      .mockResolvedValue({ ...factor(h), enabledAt: null });

    const transaction = tx(h);

    const result = await h.service.enable(
      ID,
      totp(SECRET, Math.floor(at / 30000)), SID,
    );

    expect(transaction.mfaSetting.updateMany)
      .toHaveBeenCalledOnce();

    expect(transaction.user.updateMany)
      .toHaveBeenCalledOnce();

    expect(result.recoveryCodes).toHaveLength(8);

    expect(
      new Set(result.recoveryCodes).size,
    ).toBe(8);

    expect(result.recoveryCodes[0]).toMatch(
      /^[A-F0-9]{8}-[A-F0-9]{8}$/,
    );

    expect(result.accessToken).toBe('access-token');

    const data =
      transaction.mfaSetting.updateMany
        .mock.calls[0][0].data;

    expect(data.recoveryHashes).toHaveLength(8);
    expect(data.enabledAt).toBeInstanceOf(Date);
    expect(data.pendingCipher).toBeNull();
  });

  it('rejects concurrent MFA setup modification', async () => {
    const at = clock();
    const h = harness();

    h.prisma.mfaSetting.findUnique
      .mockResolvedValue({ ...factor(h), enabledAt: null });

    const transaction = tx(h, 0);

    await expect(
      h.service.enable(
        ID,
        totp(SECRET, Math.floor(at / 30000)), SID,
      ),
    ).rejects.toBeInstanceOf(ConflictException);

    expect(transaction.user.updateMany)
      .not.toHaveBeenCalled();
  });
});

describe('MFA verification and replay protection', () => {
  it.each([
    ['missing subject', {
      purpose: 'mfa',
      sv: 7,
    }],
    ['wrong token purpose', {
      sub: ID,
      purpose: 'access',
      sv: 7,
    }],
    ['invalid session version', {
      sub: ID,
      purpose: 'mfa',
      sv: '7',
    }],
  ])('rejects challenge with %s', async (_name, payload) => {
    const h = harness();

    h.jwt.verifyAsync.mockResolvedValue(payload);

    await expect(
      h.service.verifyChallenge('challenge', '123456'),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.prisma.user.findUnique)
      .not.toHaveBeenCalled();
  });

  it('rejects a challenge for a missing user', async () => {
    const h = harness();

    h.jwt.verifyAsync.mockResolvedValue({
      sub: ID,
      purpose: 'mfa', jti: JTI, exp: Math.floor(Date.now() / 1000) + 600,
      sv: 7,
    });

    h.prisma.user.findUnique.mockResolvedValue(null);

    await expect(
      h.service.verifyChallenge('challenge', '123456'),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it.each([
    ['missing factor', null],
    ['disabled MFA', {
      enabledAt: null,
      secretCipher: 'cipher',
    }],
    ['missing secret', {
      enabledAt: new Date(),
      secretCipher: null,
    }],
  ])('rejects verification with %s', async (_name, data) => {
    const h = harness();

    challenge(h);

    h.prisma.mfaSetting.findUnique
      .mockResolvedValue(data);

    await expect(
      h.service.verifyChallenge('challenge', '123456'),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it.each([
    ['too many attempts', {
      attempts: 5,
      lockedUntil: null,
    }],
    ['active lockout', {
      attempts: 1,
      lockedUntil: new Date(Date.now() + 600000),
    }],
  ])('rejects %s', async (_name, overrides) => {
    const h = harness();

    challenge(h, {
      ...factor(h),
      ...overrides,
    });

    await expect(
      h.service.verifyChallenge('challenge', '123456'),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('accepts a valid TOTP code', async () => {
    const at = clock();
    const h = harness();

    challenge(h);

    const result = await h.service.verifyChallenge(
      'challenge',
      totp(SECRET, Math.floor(at / 30000)),
    );

    expect(result).toMatchObject({
      mfaRequired: false,
      accessToken: 'access-token',
    });

    expect(h.prisma.mfaSetting.updateMany)
      .toHaveBeenCalledOnce();

    expect(h.tx.mfaLoginChallenge.deleteMany).toHaveBeenCalledOnce();
    expect(h.sessions.issueInTransaction).toHaveBeenCalledWith(h.tx, ID, 7);
  });

  it('accepts TOTP from the previous time window', async () => {
    const at = clock();
    const h = harness();

    challenge(h);

    await expect(
      h.service.verifyChallenge(
        'challenge',
        totp(SECRET, Math.floor(at / 30000) - 1),
      ),
    ).resolves.toHaveProperty('accessToken');
  });

  it('rejects replayed authenticator codes', async () => {
    const at = clock();
    const h = harness();

    challenge(h, {
      ...factor(h),
      lastUsedStep: Math.floor(at / 30000) + 1,
    });

    await expect(
      h.service.verifyChallenge(
        'challenge',
        totp(SECRET, Math.floor(at / 30000)),
      ),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.mfaSetting.update).toHaveBeenCalledOnce();
    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('rejects concurrent consumption of a TOTP', async () => {
    const at = clock();
    const h = harness();

    challenge(h);

    h.prisma.mfaSetting.updateMany.mockResolvedValue({
      count: 0,
    });

    await expect(
      h.service.verifyChallenge(
        'challenge',
        totp(SECRET, Math.floor(at / 30000)),
      ),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects malformed verification codes', async () => {
    const h = harness();

    challenge(h);

    await expect(
      h.service.verifyChallenge('challenge', 'bad code'),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.mfaSetting.update).toHaveBeenCalledOnce();
    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('accepts and consumes a recovery code', async () => {
    const h = harness(); const digest = h.inside.recoveryHash(RECOVERY);
    challenge(h, { ...factor(h), recoveryHashes: [digest] });
    await expect(h.service.verifyChallenge('challenge', RECOVERY)).resolves.toHaveProperty('accessToken');
    expect(h.tx.mfaSetting.update).toHaveBeenCalledWith({ where: { userId: ID }, data: { recoveryHashes: [], attempts: 0, lockedUntil: null } });
    expect(h.tx.mfaLoginChallenge.deleteMany).toHaveBeenCalledOnce();
  });

  it('rejects an already-consumed recovery code', async () => {
    const h = harness();

    challenge(h);

    await expect(
      h.service.verifyChallenge('challenge', RECOVERY),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.mfaSetting.update).toHaveBeenCalledOnce();
    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('normalizes recovery code case and hyphens', () => {
    const h = harness();

    expect(
      h.inside.recoveryHash('ABCD-1234'),
    ).toBe(
      h.inside.recoveryHash('abcd1234'),
    );
  });
});

describe('MFA notifications and disabling', () => {
  it('does not queue an unverified recipient', async () => {
    const h = harness(); h.tx.user.findUnique.mockResolvedValue({ email: EMAIL, emailVerifiedAt: null });
    await enqueueSecurityNotification(h.tx as never, ID, 'MFA_ENABLED');
    expect(h.tx.securityNotification.create).not.toHaveBeenCalled();
  });
  it('rejects a missing notification account', async () => {
    const h = harness(); h.tx.user.findUnique.mockResolvedValue(null);
    await expect(enqueueSecurityNotification(h.tx as never, ID, 'MFA_ENABLED')).rejects.toThrow('Notification account no longer exists');
    expect(h.tx.securityNotification.create).not.toHaveBeenCalled();
  });
  it('queues MFA enable and disable notifications without network I/O', async () => {
    const h = harness(); const send = vi.fn(); vi.stubGlobal('fetch', send);
    await enqueueSecurityNotification(h.tx as never, ID, 'MFA_ENABLED');
    await enqueueSecurityNotification(h.tx as never, ID, 'MFA_DISABLED');
    expect(h.tx.securityNotification.create).toHaveBeenCalledTimes(2);
    for (const kind of ['MFA_ENABLED', 'MFA_DISABLED']) expect(h.tx.securityNotification.create).toHaveBeenCalledWith({ data: { userId: ID, recipient: EMAIL, kind, language: 'en' } });
    expect(send).not.toHaveBeenCalled();
  });
  it('retains an outbox job for retry when mail transport fails', async () => {
    const jobs = { updateMany: vi.fn().mockResolvedValue({ count: 1 }), deleteMany: vi.fn().mockResolvedValue({ count: 0 }), findMany: vi.fn().mockResolvedValue([{ id: JTI, recipient: EMAIL, kind: 'MFA_ENABLED', language: 'en', attempts: 0, createdAt: new Date() }]) };
    const worker = new SecurityNotificationService({ securityNotification: jobs } as never, { get: () => 'test-only' } as never);
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('mail unavailable')));
    await (worker as unknown as { processBatch(): Promise<void> }).processBatch();
    expect(jobs.updateMany).toHaveBeenLastCalledWith(expect.objectContaining({ data: expect.objectContaining({ claimId: null, notBefore: expect.any(Date) }) }));
    expect(jobs.updateMany.mock.calls.at(-1)?.[0].data).not.toHaveProperty('failedAt');
  });

  it('disables MFA and invalidates the old session', async () => {
    const h = harness();

    h.tx.mfaSetting.findUnique.mockResolvedValue({ ...factor(h), recoveryHashes: [h.inside.recoveryHash(RECOVERY)] });

    const transaction = tx(h);

    await expect(
      h.service.disable(ID, RECOVERY, SID),
    ).resolves.toHaveProperty('accessToken');

    expect(h.tx.mfaSetting.update).toHaveBeenCalledWith({ where: { userId: ID }, data: { recoveryHashes: [], attempts: 0, lockedUntil: null } });

    expect(transaction.mfaSetting.deleteMany)
      .toHaveBeenCalledOnce();

    expect(transaction.user.updateMany)
      .toHaveBeenCalledOnce();
  });

  it('rejects concurrent deletion of MFA settings', async () => {
    const h = harness();

    h.tx.mfaSetting.findUnique.mockResolvedValue({ ...factor(h), recoveryHashes: [h.inside.recoveryHash(RECOVERY)] });

    const transaction = tx(h, 1, 0);

    await expect(
      h.service.disable(ID, RECOVERY, SID),
    ).rejects.toBeInstanceOf(ConflictException);

    expect(transaction.user.updateMany)
      .not.toHaveBeenCalled();
  });
});

describe('MfaController routing', () => {
  it('delegates status and setup', async () => {
    const mfa = {
      status: vi.fn().mockResolvedValue({
        enabled: false,
      }),
      setup: vi.fn().mockResolvedValue({
        secret: 'secret',
      }),
    };

    const controller = new MfaController(mfa as never);

    const req = {
      user: {
        id: ID,
        email: EMAIL,
      },
      sessionId: SID,
    };

    await expect(controller.status(req)).resolves.toEqual({
      enabled: false,
    });

    await expect(controller.setup(req)).resolves.toEqual({
      secret: 'secret',
    });

    expect(mfa.status).toHaveBeenCalledWith(ID);

    expect(mfa.setup).toHaveBeenCalledWith(
      ID,
      SID,
    );
  });

  it('delegates enable, verify and disable', async () => {
    const mfa = {
      enable: vi.fn().mockResolvedValue({
        enabled: true,
      }),
      verifyChallenge: vi.fn().mockResolvedValue({
        accessToken: 'token',
      }),
      disable: vi.fn().mockResolvedValue({
        enabled: false,
      }),
    };

    const controller = new MfaController(mfa as never);

    const req = {
      user: {
        id: ID,
        email: EMAIL,
      },
      sessionId: SID,
    };

    await controller.enable(req, {
      code: '123456',
    });

    await controller.verify({
      code: '123456',
      challengeToken: 'challenge-token',
    });

    await controller.disable(req, {
      code: RECOVERY,
    });

    expect(mfa.enable).toHaveBeenCalledWith(
      ID,
      '123456', SID,
    );

    expect(mfa.verifyChallenge).toHaveBeenCalledWith(
      'challenge-token',
      '123456',
    );

    expect(mfa.disable).toHaveBeenCalledWith(
      ID,
      RECOVERY, SID,
    );
  });
});

function guardHarness(authorization?: string) {
  const user = {
    id: ID,
    email: EMAIL,
    role: 'PATIENT',
    isActive: true,
    sessionVersion: 3,
  };

  const prisma = {
    user: {
      findUnique: vi.fn().mockResolvedValue(user),
    },
    authSession: {
      findUnique: vi.fn().mockResolvedValue({
        userId: ID,
        revokedAt: null,
        expiresAt: new Date(Date.now() + 600000), absoluteExpiresAt: new Date(Date.now() + 1200000), lastActiveAt: new Date(),
        sessionVersion: 3,
      }),
    },
  };

  const jwt = {
    verifyAsync: vi.fn().mockResolvedValue({
      sub: ID,
      purpose: 'access',
      sid: ID,
      sv: 3, exp: Math.floor(Date.now() / 1000) + 600,
    }),
  };

  const guard = new JwtAuthGuard(
    jwt as never,
    prisma as never,
  );

  const req = {
    headers: {
      authorization,
    },
    user: undefined as unknown,
  };

  const context = {
    switchToHttp: () => ({
      getRequest: () => req,
    }),
  } as unknown as ExecutionContext;

  return {
    user,
    prisma,
    jwt,
    guard,
    req,
    context,
  };
}

describe('JwtAuthGuard security', () => {
  it.each([
    ['missing header', undefined],
    ['wrong scheme', 'Basic token'],
    ['empty bearer token', 'Bearer '],
  ])('rejects %s', async (_name, header) => {
    const h = guardHarness(header);

    await expect(
      h.guard.canActivate(h.context),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.jwt.verifyAsync)
      .not.toHaveBeenCalled();
  });

  it('rejects invalid JWT signatures or expiration', async () => {
    const h = guardHarness('Bearer token');

    h.jwt.verifyAsync.mockRejectedValue(
      new Error('expired'),
    );

    await expect(
      h.guard.canActivate(h.context),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it.each([
    ['MFA challenge token', {
      sub: ID,
      purpose: 'mfa',
      sv: 3,
    }],
    ['missing session version', {
      sub: ID,
      purpose: 'access',
    }],
    ['missing subject', {
      purpose: 'access',
      sv: 3,
    }],
    ['invalid subject', {
      sub: 'not-a-uuid',
      purpose: 'access',
      sv: 3,
    }],
  ])('rejects %s', async (_name, payload) => {
    const h = guardHarness('Bearer token');

    h.jwt.verifyAsync.mockResolvedValue(payload);

    await expect(
      h.guard.canActivate(h.context),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.prisma.user.findUnique)
      .not.toHaveBeenCalled();
  });

  it.each([
    ['unknown user', null],
    ['inactive account', {
      id: ID,
      isActive: false,
      sessionVersion: 3,
    }],
    ['outdated session', {
      id: ID,
      isActive: true,
      sessionVersion: 4,
    }],
  ])('rejects %s', async (_name, user) => {
    const h = guardHarness('Bearer token');

    h.prisma.user.findUnique.mockResolvedValue(user);

    await expect(
      h.guard.canActivate(h.context),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('returns a sanitized user for valid access tokens', async () => {
    const h = guardHarness('Bearer token');

    await expect(
      h.guard.canActivate(h.context),
    ).resolves.toBe(true);

    expect(h.req.user).toMatchObject({
      id: ID,
      email: EMAIL,
      role: 'PATIENT',
    });

    expect(h.req.user)
      .not.toHaveProperty('sessionVersion');

    expect(h.req.user)
      .not.toHaveProperty('isActive');

    expect(h.jwt.verifyAsync).toHaveBeenCalledWith(
      'token',
      expect.objectContaining({
        algorithms: ['HS256'],
      }),
    );
  });
});


describe('MFA final uncovered branches', () => {

  it('rejects a malformed authenticator code during setup', async () => {
    const h = harness();

    h.prisma.mfaSetting.findUnique.mockResolvedValue({
      ...factor(h),
      enabledAt: null,
    });

    await expect(
      h.service.enable(ID, 'NOT-A-CODE', SID),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.mfaSetting.updateMany).not.toHaveBeenCalled();
    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('rejects a corrupted Base32 authenticator secret', async () => {
    const h = harness();

    h.prisma.mfaSetting.findUnique.mockResolvedValue({
      ...factor(h),
      enabledAt: null,
      pendingCipher: h.inside.encrypt('INVALID!'),
    });

    await expect(
      h.service.enable(ID, '123456', SID),
    ).rejects.toThrow('Setup expired');

    expect(h.tx.mfaSetting.updateMany).not.toHaveBeenCalled();
    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('rejects a well-formed but incorrect TOTP code', async () => {
    const h = harness();

    h.prisma.mfaSetting.findUnique.mockResolvedValue({
      ...factor(h),
      enabledAt: null,
    });

    const step = Math.floor(Date.now() / 30000);

    const valid = new Set([
      totp(SECRET, step - 1),
      totp(SECRET, step),
      totp(SECRET, step + 1),
    ]);

    const wrongCode = [
      '000000',
      '000001',
      '000002',
      '000003',
    ].find(code => !valid.has(code));

    if (!wrongCode) {
      throw new Error('Test fixture could not find an invalid code');
    }

    await expect(
      h.service.enable(ID, wrongCode, SID),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.mfaSetting.updateMany).not.toHaveBeenCalled();
    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });
});

// Final coverage closeout

describe('Final MFA security boundaries', () => {
  it('rejects corrupted persisted Base32 secrets', async () => {
    const h = harness();

    challenge(h, {
      ...factor(h),
      secretCipher: h.inside.encrypt('INVALID!')
    });

    await expect(h.service.verifyChallenge('challenge', '123456'))
      .rejects.toThrow('Invalid TOTP secret');

    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('rejects a stale MFA login account version', async () => {
    const h = harness();

    await expect(h.service.loginResult({
      id: ID, sessionVersion: 6
    })).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('rejects password-based MFA without verified email', async () => {
    const h = harness();

    h.tx.user.findUnique.mockResolvedValue({
      id: ID,
      isActive: true,
      sessionVersion: 7,
      passwordHash: 'test-hash',
      emailVerifiedAt: null
    });

    await expect(h.service.setup(ID, SID))
      .rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('preserves lockout while it is active', async () => {
    const h = harness();

    h.tx.mfaSetting.findUnique.mockResolvedValue({
      ...factor(h),
      enabledAt: null,
      attempts: 5,
      lockedUntil: new Date(Date.now() + 60000)
    });

    await expect(h.service.setup(ID, SID))
      .rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.mfaSetting.upsert).not.toHaveBeenCalled();
  });

  it('permits fresh setup after the lockout expires', async () => {
    const h = harness();

    h.tx.mfaSetting.findUnique.mockResolvedValue({
      ...factor(h),
      enabledAt: null,
      attempts: 5,
      lockedUntil: new Date(Date.now() - 60000)
    });

    await expect(h.service.setup(ID, SID))
      .resolves.toHaveProperty('secret');

    expect(h.tx.mfaSetting.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        update: expect.objectContaining({
          attempts: 0,
          lockedUntil: null
        })
      })
    );
  });

  it('records the fifth failed setup attempt and locks the factor', async () => {
    const h = harness();

    h.tx.mfaSetting.findUnique.mockResolvedValue({
      ...factor(h),
      enabledAt: null,
      attempts: 4
    });

    await expect(h.service.enable(ID, 'invalid', SID))
      .rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.mfaSetting.update).toHaveBeenCalledWith({
      where: { userId: ID },
      data: {
        attempts: 5,
        lockedUntil: expect.any(Date)
      }
    });
  });

  it('rejects setup proof bound to a different session', async () => {
    const h = harness();

    h.tx.mfaSetting.findUnique.mockResolvedValue({
      ...factor(h),
      enabledAt: null,
      pendingCipher: h.inside.encrypt(JSON.stringify([
        'ted:mfa-setup:v2', ID, JTI, 7, SECRET
      ]))
    });

    await expect(h.service.enable(ID, '123456', SID))
      .rejects.toThrow('belongs to another session');

    expect(h.tx.mfaSetting.updateMany).not.toHaveBeenCalled();
  });

  it('rejects attempts to enable a locked pending factor', async () => {
    const h = harness();

    h.tx.mfaSetting.findUnique.mockResolvedValue({
      ...factor(h),
      enabledAt: null,
      attempts: 5,
      lockedUntil: new Date(Date.now() + 60000)
    });

    await expect(h.service.enable(ID, '123456', SID))
      .rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.mfaSetting.updateMany).not.toHaveBeenCalled();
  });

  it('rejects concurrent account-version rotation during MFA enable', async () => {
    const at = clock();
    const h = harness();

    h.tx.mfaSetting.findUnique.mockResolvedValue({
      ...factor(h), enabledAt: null
    });

    h.tx.user.updateMany.mockResolvedValue({ count: 0 });

    await expect(h.service.enable(
      ID, totp(SECRET, Math.floor(at / 30000)), SID
    )).rejects.toBeInstanceOf(ConflictException);

    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('rejects an expired or consumed MFA login challenge', async () => {
    const h = harness();
    challenge(h);
    h.tx.mfaLoginChallenge.findFirst.mockResolvedValue(null);

    await expect(h.service.verifyChallenge('challenge', '123456'))
      .rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('rejects concurrent login challenge consumption', async () => {
    const at = clock();
    const h = harness();

    challenge(h);

    h.tx.mfaLoginChallenge.deleteMany.mockResolvedValue({ count: 0 });

    await expect(h.service.verifyChallenge(
      'challenge', totp(SECRET, Math.floor(at / 30000))
    )).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.sessions.issueInTransaction).not.toHaveBeenCalled();
  });

  it('does not disable MFA when verification fails', async () => {
    const h = harness();

    h.tx.mfaSetting.findUnique.mockResolvedValue(factor(h));

    await expect(h.service.disable(ID, 'invalid', SID))
      .rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.mfaSetting.deleteMany).not.toHaveBeenCalled();
  });
});
