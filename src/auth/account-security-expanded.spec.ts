
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  BadRequestException,
  ConflictException,
  UnauthorizedException,
  ServiceUnavailableException,
  HttpException,
} from '@nestjs/common';

import { hash, compare } from 'bcryptjs';
import { createHmac } from 'node:crypto';

import { AccountDataController } from './account/account-data.controller';
import { ConnectedAccountsController } from './account/connected-accounts.controller';
import { ConnectedAccountsService } from './account/connected-accounts.service';
import { AuthSessionController } from './sessions/auth-session.controller';
import { EmailChangeService } from './email/email-change.service';
import { GoogleActionChallengeService } from './google/google-action-challenge.service';
import {
  SecurityActivityService,
  securityActivityCutoff,
  lockSecurityActivityUser,
  parseActivityCursor,
} from './security/security-activity.service';

const UID = '11111111-1111-4111-8111-111111111111';
const SID = '22222222-2222-4222-8222-222222222222';
const RID = '33333333-3333-4333-8333-333333333333';
const EMAIL = 'patient@gmail.com';
const NEXT = 'next@example.test';
const PASSWORD = 'TestPassword123!';
const TOKEN = 'test-only-google-id-token';
const SECRET = 'test-only-verification-secret';

const req = { user: { id: UID }, sessionId: SID };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('Account data controller ownership contracts', () => {
  it('delegates all five routes with the authenticated session', async () => {
    const service = {
      exportAccount: vi.fn().mockResolvedValue({}),
      deleteAccount: vi.fn().mockResolvedValue({}),
      requestGoogleDataChallenge: vi.fn().mockResolvedValue({}),
      exportGoogleAccount: vi.fn().mockResolvedValue({}),
      deleteGoogleAccount: vi.fn().mockResolvedValue({}),
    };

    const c = new AccountDataController(service as never);

    const exp = { currentPassword: PASSWORD, mfaCode: '123456' };
    const del = { ...exp, confirmation: 'DELETE' };
    const challenge = { action: 'EXPORT_DATA' as const, idToken: TOKEN };
    const proof = { requestId: RID, emailCode: '12345678' };
    const gdel = { ...proof, confirmation: 'DELETE' };

    await c.exportAccount(req, exp);
    await c.deleteAccount(req, del);
    await c.requestGoogleDataChallenge(req, challenge);
    await c.exportGoogleAccount(req, proof);
    await c.deleteGoogleAccount(req, gdel);

    expect(service.exportAccount).toHaveBeenCalledWith(req, exp);
    expect(service.deleteAccount).toHaveBeenCalledWith(req, del);
    expect(service.requestGoogleDataChallenge).toHaveBeenCalledWith(req, challenge);
    expect(service.exportGoogleAccount).toHaveBeenCalledWith(req, proof);
    expect(service.deleteGoogleAccount).toHaveBeenCalledWith(req, gdel);
  });
});

describe('Connected account controller contracts', () => {
  it('passes session ownership into every sensitive operation', async () => {
    const service = {
      list: vi.fn(),
      requestGooglePasswordChallenge: vi.fn(),
      setGooglePassword: vi.fn(),
      changeGoogle: vi.fn(),
    };

    const c = new ConnectedAccountsController(service as never);

    await c.list(req);
    await c.requestGooglePasswordChallenge(req, { idToken: TOKEN });

    await c.setGooglePassword(req, {
      requestId: RID,
      emailCode: '12345678',
      newPassword: PASSWORD,
      mfaCode: '123456'
    });

    await c.link(req, {
      idToken: TOKEN,
      currentPassword: PASSWORD,
      mfaCode: '123456'
    });

    await c.unlink(req, {
      currentPassword: PASSWORD,
      mfaCode: '123456'
    });

    expect(service.list).toHaveBeenCalledWith(UID);
    expect(service.requestGooglePasswordChallenge)
      .toHaveBeenCalledWith(UID, SID, TOKEN);

    expect(service.setGooglePassword)
      .toHaveBeenCalledWith(UID, SID, RID, '12345678', PASSWORD, '123456');

    expect(service.changeGoogle)
      .toHaveBeenNthCalledWith(1, UID, SID, 'link', PASSWORD, '123456', TOKEN);

    expect(service.changeGoogle)
      .toHaveBeenNthCalledWith(2, UID, SID, 'unlink', PASSWORD, '123456');
  });
});

describe('Session controller ownership contracts', () => {
  it('uses the authenticated owner for listing and revoking devices', async () => {
    const service = {
      listSessions: vi.fn(),
      revokeSession: vi.fn(),
      listSecurityActivity: vi.fn(),
    };

    const c = new AuthSessionController(service as never);

    await c.listSessions(req);
    await c.revokeSession(req, RID.toUpperCase());
    await c.listSecurityActivity(req, 'cursor');

    expect(service.listSessions).toHaveBeenCalledWith(UID, SID);
    expect(service.revokeSession).toHaveBeenCalledWith(UID, SID, RID);
    expect(service.listSecurityActivity).toHaveBeenCalledWith(UID, 'cursor');
  });
});

async function fixture() {
  const user = {
    id: UID,
    email: EMAIL,
    isActive: true,
    role: 'PATIENT',
    passwordHash: await hash(PASSWORD, 4),
    emailVerifiedAt: new Date(),
    sessionVersion: 4,
    preferredLanguage: 'en',
    _count: { socialAccounts: 0 },
    socialAccounts: []
  };

  const tx = {
    $queryRaw: vi.fn().mockResolvedValue([]),
    user: {
      findUnique: vi.fn().mockImplementation(async (query) =>
        query.where.id ? user : null
      ),
      findFirst: vi.fn().mockResolvedValue({ id: UID }),
      updateMany: vi.fn().mockResolvedValue({ count: 1 })
    },
    authSession: {
      findFirst: vi.fn().mockResolvedValue({ id: SID }),
      updateMany: vi.fn().mockResolvedValue({ count: 1 })
    },
    socialAccount: {
      findUnique: vi.fn().mockResolvedValue(null),
      create: vi.fn().mockResolvedValue({}),
      delete: vi.fn().mockResolvedValue({})
    },
    passwordResetCode: {
      deleteMany: vi.fn().mockResolvedValue({ count: 1 })
    },
    emailVerificationCode: {
      updateMany: vi.fn().mockResolvedValue({ count: 1 })
    },
    emailChangeRequest: {
      findUnique: vi.fn().mockResolvedValue(null),
      upsert: vi.fn().mockResolvedValue({}),
      updateMany: vi.fn().mockResolvedValue({ count: 1 })
    },
    googleActionChallenge: {
      findUnique: vi.fn().mockResolvedValue(null),
      upsert: vi.fn().mockResolvedValue({}),
      updateMany: vi.fn().mockResolvedValue({ count: 1 })
    },
    securityEvent: { create: vi.fn().mockResolvedValue({}) },
    securityNotification: { create: vi.fn().mockResolvedValue({}) }
  };

  const prisma = {
    ...tx,
    $transaction: vi.fn(
      async (fn: (client: typeof tx) => Promise<unknown>) => fn(tx)
    )
  };

  const config = {
    get: vi.fn().mockImplementation((key: string) => {
      const values: Record<string, string> = {
        GOOGLE_WEB_CLIENT_ID: 'test-client',
        RESEND_API_KEY: 'test-key',
        RESET_EMAIL_FROM: 'sender@example.test'
      };
      return values[key];
    }),
    getOrThrow: vi.fn().mockReturnValue(SECRET)
  };

  const mfa = {
    verifySensitiveActionInTransaction: vi.fn().mockResolvedValue(true)
  };

  const google = {
    request: vi.fn().mockResolvedValue({ requestId: RID }),
    execute: vi.fn(async (
      _proof: unknown,
      operation: (
        client: typeof tx,
        identity: {
          userId: string;
          email: string;
          sessionVersion: number;
        }
      ) => Promise<unknown>
    ) => operation(tx, {
      userId: UID,
      email: EMAIL,
      sessionVersion: 4
    }))
  };

  const connections = new ConnectedAccountsService(
    prisma as never, config as never, mfa as never, google as never
  );

  const emailChange = new EmailChangeService(
    prisma as never, config as never, mfa as never
  );

  const challenge = new GoogleActionChallengeService(
    prisma as never, config as never, mfa as never
  );

  function mockGoogle(service: object, payload: unknown) {
    const internal = service as {
      google: { verifyIdToken: (...args: unknown[]) => Promise<unknown> }
    };

    return vi.spyOn(internal.google, 'verifyIdToken')
      .mockResolvedValue({ getPayload: () => payload });
  }

  const googlePayload = {
    sub: 'test-google-subject',
    email: EMAIL,
    email_verified: true
  };

  const send = vi.fn().mockResolvedValue(
    new Response(null, { status: 200 })
  );

  vi.stubGlobal('fetch', send);

  return {
    user, tx, prisma, config, mfa, google,
    connections, emailChange, challenge,
    mockGoogle, googlePayload, send
  };
}

describe('Connected accounts service', () => {
  it('rejects inactive accounts', async () => {
    const h = await fixture();

    h.tx.user.findUnique.mockResolvedValue(null);

    await expect(h.connections.list(UID))
      .rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('lists a verified password account', async () => {
    const h = await fixture();

    await expect(h.connections.list(UID)).resolves.toMatchObject({
      hasPassword: true,
      canManageConnections: true,
      canSetPassword: false
    });
  });

  it('binds password setup proof to the current session', async () => {
    const h = await fixture();

    await h.connections.requestGooglePasswordChallenge(UID, SID, TOKEN);

    expect(h.google.request)
      .toHaveBeenCalledWith(UID, SID, 'SET_PASSWORD', TOKEN);
  });

  it.each(['short', 'a'.repeat(73)])(
    'rejects invalid new passwords',
    async password => {
      const h = await fixture();

      await expect(h.connections.setGooglePassword(
        UID, SID, RID, '12345678', password
      )).rejects.toBeInstanceOf(BadRequestException);

      expect(h.google.execute).not.toHaveBeenCalled();
    }
  );

  it('hashes a Google-only account password and revokes sessions', async () => {
    const h = await fixture();

    await expect(h.connections.setGooglePassword(
      UID, SID, RID, '12345678', PASSWORD
    )).resolves.toHaveProperty('message');

    const change = h.tx.user.updateMany.mock.calls[0][0];

    expect(change.where.passwordHash).toBeNull();
    expect(change.data.sessionVersion).toEqual({ increment: 1 });
    expect(await compare(PASSWORD, change.data.passwordHash)).toBe(true);

    expect(h.tx.authSession.updateMany).toHaveBeenCalledOnce();

    expect(h.tx.securityNotification.create)
      .toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({
          userId: UID,
          kind: 'PASSWORD_CHANGED'
        })
      }));

    expect(h.send).not.toHaveBeenCalled();
  });

  it('rejects a stale password-setup transaction', async () => {
    const h = await fixture();

    h.tx.user.updateMany.mockResolvedValue({ count: 0 });

    await expect(h.connections.setGooglePassword(
      UID, SID, RID, '12345678', PASSWORD
    )).rejects.toBeInstanceOf(ConflictException);

    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();
  });

  it('rejects a wrong current password before Google verification', async () => {
    const h = await fixture();
    const verify = h.mockGoogle(h.connections, h.googlePayload);

    await expect(h.connections.changeGoogle(
      UID, SID, 'link', 'wrong', undefined, TOKEN
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(verify).not.toHaveBeenCalled();
    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it.each([
    null,
    { sub: '', email: EMAIL, email_verified: true },
    { sub: 'subject', email: EMAIL, email_verified: false },
    { sub: 'subject', email: 'other@example.test', email_verified: true },
    { sub: 'subject', email: 'other@gmail.com', email_verified: true }
  ])('rejects a missing, unverified or mismatched identity', async payload => {
    const h = await fixture();
    h.mockGoogle(h.connections, payload);

    await expect(h.connections.changeGoogle(
      UID, SID, 'link', PASSWORD, undefined, TOKEN
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.socialAccount.create).not.toHaveBeenCalled();
  });

  it('fails closed without a configured Google client ID', async () => {
    const h = await fixture();

    h.config.get.mockReturnValue(undefined);

    await expect(h.connections.changeGoogle(
      UID, SID, 'link', PASSWORD, undefined, TOKEN
    )).rejects.toBeInstanceOf(ServiceUnavailableException);
  });

  it('rejects an expired session', async () => {
    const h = await fixture();

    h.tx.authSession.findFirst.mockResolvedValue(null);

    await expect(h.connections.changeGoogle(
      UID, SID, 'unlink', PASSWORD
    )).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.socialAccount.delete).not.toHaveBeenCalled();
  });

  it('does not modify a connection when MFA fails', async () => {
    const h = await fixture();
    h.mockGoogle(h.connections, h.googlePayload);

    h.mfa.verifySensitiveActionInTransaction.mockResolvedValue(false);

    await expect(h.connections.changeGoogle(
      UID, SID, 'link', PASSWORD, '123456', TOKEN
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.socialAccount.create).not.toHaveBeenCalled();
    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
  });

  it('links an authoritative matching identity in a transaction', async () => {
    const h = await fixture();
    h.mockGoogle(h.connections, h.googlePayload);

    await h.connections.changeGoogle(
      UID, SID, 'link', PASSWORD, '123456', TOKEN
    );

    expect(h.tx.socialAccount.create).toHaveBeenCalledWith({
      data: {
        userId: UID,
        provider: 'GOOGLE',
        providerUserId: h.googlePayload.sub
      }
    });

    expect(h.mfa.verifySensitiveActionInTransaction)
      .toHaveBeenCalledWith(h.tx, UID, SID, 4, '123456');

    expect(h.tx.user.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        data: { sessionVersion: { increment: 1 } }
      })
    );

    expect(h.tx.authSession.updateMany).toHaveBeenCalledOnce();

    expect(h.tx.securityEvent.create).toHaveBeenCalledWith({
      data: { userId: UID, type: 'GOOGLE_LINKED' }
    });

    expect(h.send).not.toHaveBeenCalled();
  });

  it('rejects a duplicate Google connection', async () => {
    const h = await fixture();
    h.mockGoogle(h.connections, h.googlePayload);

    h.tx.socialAccount.findUnique.mockResolvedValue({ id: RID });

    await expect(h.connections.changeGoogle(
      UID, SID, 'link', PASSWORD, undefined, TOKEN
    )).rejects.toBeInstanceOf(ConflictException);

    expect(h.tx.socialAccount.create).not.toHaveBeenCalled();
  });

  it('unlinks only the account belonging to the requesting owner', async () => {
    const h = await fixture();

    h.tx.socialAccount.findUnique.mockResolvedValue({ id: RID });

    await h.connections.changeGoogle(
      UID, SID, 'unlink', PASSWORD
    );

    expect(h.tx.socialAccount.delete)
      .toHaveBeenCalledWith({ where: { id: RID } });

    expect(h.tx.securityEvent.create)
      .toHaveBeenCalledWith({
        data: { userId: UID, type: 'GOOGLE_UNLINKED' }
      });

    expect(h.tx.authSession.updateMany).toHaveBeenCalledOnce();
  });

  it('rejects unlink when no Google account exists', async () => {
    const h = await fixture();

    await expect(h.connections.changeGoogle(
      UID, SID, 'unlink', PASSWORD
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.socialAccount.delete).not.toHaveBeenCalled();
  });
});

describe('Email change request security', () => {
  it('rejects the current email address', async () => {
    const h = await fixture();

    await expect(h.emailChange.request(
      UID, SID, EMAIL, PASSWORD
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('rejects an incorrect password', async () => {
    const h = await fixture();

    await expect(h.emailChange.request(
      UID, SID, NEXT, 'wrong'
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('requires successful MFA before reserving codes', async () => {
    const h = await fixture();

    h.mfa.verifySensitiveActionInTransaction.mockResolvedValue(false);

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD, '123456'
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.emailChangeRequest.upsert).not.toHaveBeenCalled();
    expect(h.send).not.toHaveBeenCalled();
  });

  it('enforces the resend cooldown', async () => {
    const h = await fixture();

    h.tx.emailChangeRequest.findUnique.mockResolvedValue({
      sentAt: new Date(),
      windowStartedAt: new Date(),
      sentInWindow: 1
    });

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('enforces the hourly sending quota', async () => {
    const h = await fixture();

    h.tx.emailChangeRequest.findUnique.mockResolvedValue({
      sentAt: new Date(Date.now() - 120000),
      windowStartedAt: new Date(Date.now() - 120000),
      sentInWindow: 5
    });

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('reserves separate mailbox codes before delivery', async () => {
    const h = await fixture();

    const result = await h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    );

    const saved = h.tx.emailChangeRequest.upsert.mock.calls[0][0].create;

    expect(saved.requestId).toBe(result.requestId);
    expect(saved.sessionId).toBe(SID);
    expect(saved.sessionVersion).toBe(4);
    expect(saved.oldEmail).toBe(EMAIL);
    expect(saved.newEmail).toBe(NEXT);
    expect(saved.oldCodeHash).toMatch(/^[a-f0-9]{64}$/);
    expect(saved.newCodeHash).toMatch(/^[a-f0-9]{64}$/);
    expect(saved.oldCodeHash).not.toBe(saved.newCodeHash);

    expect(h.send).toHaveBeenCalledTimes(2);

    expect(h.tx.emailChangeRequest.upsert.mock.invocationCallOrder[0])
      .toBeLessThan(h.send.mock.invocationCallOrder[0]);

    const first = JSON.parse(h.send.mock.calls[0][1].body);
    const second = JSON.parse(h.send.mock.calls[1][1].body);

    expect(first.to).toEqual([EMAIL]);
    expect(second.to).toEqual([NEXT]);
  });

  it('does not claim confirmed delivery when email fails', async () => {
    const h = await fixture();

    h.send.mockResolvedValue(new Response(null, { status: 500 }));

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    )).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(h.tx.emailChangeRequest.upsert).toHaveBeenCalledOnce();
    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
  });
});

describe('Google sensitive action request security', () => {
  async function googleFixture() {
    const h = await fixture();

    h.user.passwordHash = null as never;

    h.tx.socialAccount.findUnique.mockResolvedValue({
      providerUserId: h.googlePayload.sub
    });

    h.mockGoogle(h.challenge, h.googlePayload);

    return h;
  }

  it('rejects password-based accounts', async () => {
    const h = await fixture();

    h.mockGoogle(h.challenge, h.googlePayload);

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('rejects a mismatched linked identity', async () => {
    const h = await googleFixture();

    h.tx.socialAccount.findUnique.mockResolvedValue({
      providerUserId: 'different-subject'
    });

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('enforces request cooldown', async () => {
    const h = await googleFixture();

    h.tx.googleActionChallenge.findUnique.mockResolvedValue({
      sentAt: new Date(),
      windowStartedAt: new Date(),
      sentInWindow: 1
    });

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(HttpException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('enforces the verification request quota', async () => {
    const h = await googleFixture();

    h.tx.googleActionChallenge.findUnique.mockResolvedValue({
      sentAt: new Date(Date.now() - 120000),
      windowStartedAt: new Date(Date.now() - 120000),
      sentInWindow: 5
    });

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(HttpException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('stores a session-bound verification request before email', async () => {
    const h = await googleFixture();

    const result = await h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    );

    const saved = h.tx.googleActionChallenge.upsert.mock.calls[0][0].create;

    expect(saved).toMatchObject({
      userId: UID,
      sessionId: SID,
      sessionVersion: 4,
      action: 'EXPORT_DATA',
      email: EMAIL,
      requestId: result.requestId,
      attempts: 0,
      consumedAt: null
    });

    const body = JSON.parse(h.send.mock.calls[0][1].body);
    const code = body.text.match(/\b\d{8}\b/)[0];

    expect(saved.codeHash).toBe(
      createHmac('sha256', SECRET)
        .update(JSON.stringify([
          'ted:google-action:v1', UID, result.requestId,
          SID, 4, 'EXPORT_DATA', h.googlePayload.sub, EMAIL, code
        ])).digest('hex')
    );

    expect(h.tx.googleActionChallenge.upsert.mock.invocationCallOrder[0])
      .toBeLessThan(h.send.mock.invocationCallOrder[0]);
  });

  it('invalidates an undelivered request without clearing quota', async () => {
    const h = await googleFixture();

    h.send.mockResolvedValue(new Response(null, { status: 503 }));

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(h.tx.googleActionChallenge.updateMany)
      .toHaveBeenCalledWith(expect.objectContaining({
        where: expect.objectContaining({
          userId: UID,
          consumedAt: null
        }),
        data: { consumedAt: expect.any(Date) }
      }));
  });
});

describe('Security activity retention', () => {
  it('uses a 90-day retention cutoff', () => {
    vi.useFakeTimers();

    const now = new Date('2026-11-01T00:00:00.000Z');
    vi.setSystemTime(now);

    expect(securityActivityCutoff().getTime())
      .toBe(now.getTime() - 90 * 86400000);
  });

  it('accepts an omitted cursor', () => {
    expect(parseActivityCursor()).toBeNull();
  });

  it('rejects an oversized cursor', () => {
    expect(() => parseActivityCursor('a'.repeat(81)))
      .toThrow(BadRequestException);
  });

  it('takes an owner-scoped database lock', async () => {
    const query = vi.fn().mockResolvedValue([]);

    await lockSecurityActivityUser({ $queryRaw: query } as never, UID);

    expect(query).toHaveBeenCalledOnce();
    expect(query.mock.calls[0][1]).toBe(UID);
  });

  it('executes bounded retention cleanup and stops the timer', async () => {
    vi.useFakeTimers();

    const execute = vi.fn().mockResolvedValue(1);
    const service = new SecurityActivityService(
      { $executeRaw: execute } as never
    );

    service.onModuleInit();

    await vi.advanceTimersByTimeAsync(600000);
    await service.onModuleDestroy();

    expect(execute).toHaveBeenCalledOnce();

    expect(Array.from(execute.mock.calls[0][0] as string[]).join('?'))
      .toContain('LIMIT 1000');

    expect(vi.getTimerCount()).toBe(0);
  });
});


describe('Additional connection and mailbox error paths', () => {
  it('rejects an invalid connection action', async () => {
    const h = await fixture();

    await expect(h.connections.changeGoogle(
      UID, SID, 'invalid' as never, PASSWORD
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('rejects connection changes for a missing account', async () => {
    const h = await fixture();
    h.tx.user.findUnique.mockResolvedValue(null);

    await expect(h.connections.changeGoogle(
      UID, SID, 'unlink', PASSWORD
    )).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('requires verified password ownership for connection changes', async () => {
    const h = await fixture();

    h.tx.user.findUnique.mockResolvedValue({
      ...h.user, emailVerifiedAt: null
    });

    await expect(h.connections.changeGoogle(
      UID, SID, 'unlink', PASSWORD
    )).rejects.toBeInstanceOf(BadRequestException);
  });

  it('requires Google credentials when linking', async () => {
    const h = await fixture();

    await expect(h.connections.changeGoogle(
      UID, SID, 'link', PASSWORD
    )).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects provider verification errors', async () => {
    const h = await fixture();

    h.mockGoogle(h.connections, h.googlePayload)
      .mockRejectedValue(new Error('invalid provider credential'));

    await expect(h.connections.changeGoogle(
      UID, SID, 'link', PASSWORD, undefined, TOKEN
    )).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects a concurrent account change during linking', async () => {
    const h = await fixture();

    h.mockGoogle(h.connections, h.googlePayload);

    h.tx.user.findUnique
      .mockResolvedValueOnce(h.user)
      .mockResolvedValueOnce({
        ...h.user, sessionVersion: 5
      });

    await expect(h.connections.changeGoogle(
      UID, SID, 'link', PASSWORD, undefined, TOKEN
    )).rejects.toBeInstanceOf(ConflictException);
  });

  it('rejects a connection version update that loses CAS', async () => {
    const h = await fixture();

    h.mockGoogle(h.connections, h.googlePayload);
    h.tx.user.updateMany.mockResolvedValue({ count: 0 });

    await expect(h.connections.changeGoogle(
      UID, SID, 'link', PASSWORD, undefined, TOKEN
    )).rejects.toBeInstanceOf(ConflictException);

    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();
  });

  it('rejects an invalid email change target', async () => {
    const h = await fixture();

    await expect(h.emailChange.request(
      UID, SID, '', PASSWORD
    )).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects email changes without an active account', async () => {
    const h = await fixture();

    h.tx.user.findUnique.mockResolvedValue(null);

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    )).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects mailbox changes for linked sign-in accounts', async () => {
    const h = await fixture();

    h.tx.user.findUnique.mockResolvedValue({
      ...h.user, _count: { socialAccounts: 1 }
    });

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    )).rejects.toBeInstanceOf(BadRequestException);
  });

  it('fails closed when email delivery is not configured', async () => {
    const h = await fixture();

    h.config.get.mockReturnValue(undefined);

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    )).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('rejects a session that expires before email change', async () => {
    const h = await fixture();

    h.tx.authSession.findFirst.mockResolvedValue(null);

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    )).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects malformed dual-mailbox verification codes', async () => {
    const h = await fixture();

    await expect(h.emailChange.confirm(
      UID, SID, RID, 'abc', '12345678'
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
  });

  it('rejects invalid Google verification action', async () => {
    const h = await fixture();

    await expect(h.challenge.request(
      UID, SID, 'INVALID' as never, TOKEN
    )).rejects.toBeInstanceOf(BadRequestException);
  });

  it('requires a configured Google audience', async () => {
    const h = await fixture();

    h.config.get.mockReturnValue(undefined);

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(ServiceUnavailableException);
  });

  it('rejects a malformed Google credential', async () => {
    const h = await fixture();

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', 'short'
    )).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects Google provider verification failures', async () => {
    const h = await fixture();

    h.mockGoogle(h.challenge, h.googlePayload)
      .mockRejectedValue(new Error('provider unavailable'));

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(BadRequestException);
  });

  it.each([
    null,
    { sub: '', email: EMAIL, email_verified: true },
    { sub: 'subject', email: EMAIL, email_verified: false },
    { sub: 'subject', email: ' '.repeat(3), email_verified: true }
  ])('rejects incomplete Google identity proof', async payload => {
    const h = await fixture();

    h.mockGoogle(h.challenge, payload);

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.send).not.toHaveBeenCalled();
  });
});

// Final coverage closeout

describe('Final connection and mailbox race conditions', () => {
  it('maps duplicate Google identity insertion to conflict', async () => {
    const h = await fixture();
    h.mockGoogle(h.connections, h.googlePayload);

    const { Prisma } = await import('@prisma/client');

    h.tx.socialAccount.create.mockRejectedValue(
      new Prisma.PrismaClientKnownRequestError(
        'test duplicate',
        { code: 'P2002', clientVersion: '6.19.3' }
      )
    );

    await expect(h.connections.changeGoogle(
      UID, SID, 'link', PASSWORD, undefined, TOKEN
    )).rejects.toBeInstanceOf(ConflictException);

    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();
  });

  it.each([
    { isActive: false },
    { emailVerifiedAt: null },
    { passwordHash: null }
  ])('rejects changed mailbox authorization inside transaction', async changes => {
    const h = await fixture();

    h.tx.user.findUnique
      .mockResolvedValueOnce(h.user)
      .mockResolvedValueOnce({ ...h.user, ...changes });

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    )).rejects.toBeInstanceOf(
      changes.passwordHash === null
        ? BadRequestException
        : UnauthorizedException
    );

    expect(h.tx.emailChangeRequest.upsert).not.toHaveBeenCalled();
  });

  it('rejects a changed email account version after locking', async () => {
    const h = await fixture();

    h.tx.user.findUnique
      .mockResolvedValueOnce(h.user)
      .mockResolvedValueOnce({ ...h.user, sessionVersion: 5 });

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    )).rejects.toBeInstanceOf(ConflictException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('rejects an email already owned by another account', async () => {
    const h = await fixture();

    h.tx.user.findUnique
      .mockResolvedValueOnce(h.user)
      .mockResolvedValueOnce(h.user)
      .mockResolvedValueOnce({ id: RID });

    await expect(h.emailChange.request(
      UID, SID, NEXT, PASSWORD
    )).rejects.toBeInstanceOf(ConflictException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('preserves the mailbox verification quota in the current window', async () => {
    const h = await fixture();
    const started = new Date(Date.now() - 180000);

    h.tx.emailChangeRequest.findUnique.mockResolvedValue({
      sentAt: new Date(Date.now() - 120000),
      windowStartedAt: started,
      sentInWindow: 2
    });

    await h.emailChange.request(UID, SID, NEXT, PASSWORD);

    expect(h.tx.emailChangeRequest.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        create: expect.objectContaining({
          sentInWindow: 3,
          windowStartedAt: started
        })
      })
    );
  });
});

describe('Final Google verification request boundaries', () => {
  async function prepare() {
    const h = await fixture();

    h.user.passwordHash = null as never;

    h.tx.socialAccount.findUnique.mockResolvedValue({
      providerUserId: h.googlePayload.sub
    });

    h.mockGoogle(h.challenge, h.googlePayload);

    return h;
  }

  it('rejects invalid authenticated identifiers', async () => {
    const h = await prepare();

    await expect(h.challenge.request(
      'invalid', SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('rejects a missing active Google account', async () => {
    const h = await prepare();
    h.tx.user.findUnique.mockResolvedValue(null);

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects an inactive session', async () => {
    const h = await prepare();
    h.tx.authSession.findFirst.mockResolvedValue(null);

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('requires an existing linked Google identity', async () => {
    const h = await prepare();
    h.tx.socialAccount.findUnique.mockResolvedValue(null);

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it('fails closed when Google verification email settings are missing', async () => {
    const h = await prepare();

    h.config.get.mockImplementation((key: string) =>
      key === 'GOOGLE_WEB_CLIENT_ID' ? 'test-client' : undefined
    );

    await expect(h.challenge.request(
      UID, SID, 'EXPORT_DATA', TOKEN
    )).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(h.send).not.toHaveBeenCalled();
  });

  it.each([true, false])(
    'checks account deletion eligibility before sending proof: %s',
    async eligible => {
      const h = await prepare();

      h.tx.user.findFirst.mockResolvedValue(
        eligible ? { id: UID } : null
      );

      const request = h.challenge.request(
        UID, SID, 'DELETE_ACCOUNT', TOKEN
      );

      if (eligible) {
        await expect(request).resolves.toHaveProperty('requestId');
        expect(h.send).toHaveBeenCalledOnce();
      } else {
        await expect(request).rejects.toBeInstanceOf(BadRequestException);
        expect(h.send).not.toHaveBeenCalled();
      }
    }
  );

  it('increments the existing Google challenge quota', async () => {
    const h = await prepare();
    const started = new Date(Date.now() - 180000);

    h.tx.googleActionChallenge.findUnique.mockResolvedValue({
      sentAt: new Date(Date.now() - 120000),
      windowStartedAt: started,
      sentInWindow: 2
    });

    await h.challenge.request(UID, SID, 'EXPORT_DATA', TOKEN);

    expect(h.tx.googleActionChallenge.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        create: expect.objectContaining({
          sentInWindow: 3,
          windowStartedAt: started
        })
      })
    );
  });
});


describe('Last two defensive coverage boundaries', () => {
  it('rejects a corrupted identity at the final transaction boundary', async () => {
    const h = await fixture();

    const identity = {
      subject: h.googlePayload.sub,
      email: EMAIL
    };

    const verifier = vi.spyOn(
      h.connections as unknown as {
        verifyGoogle(token: string): Promise<{
          subject: string;
          email: string;
        }>;
      },
      'verifyGoogle'
    ).mockResolvedValue(identity);

    h.tx.socialAccount.findUnique.mockImplementation(async () => {
      identity.email = 'different@example.test';
      return null;
    });

    await expect(
      h.connections.changeGoogle(
        UID,
        SID,
        'link',
        PASSWORD,
        undefined,
        TOKEN
      )
    ).rejects.toThrow('Google identity does not match.');

    expect(verifier).toHaveBeenCalledWith(TOKEN);

    expect(h.prisma.$transaction).toHaveBeenCalledOnce();

    expect(h.tx.socialAccount.create).not.toHaveBeenCalled();

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();

    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();

    expect(h.tx.securityNotification.create).not.toHaveBeenCalled();
  });

  it('fails closed when mail configuration disappears after reservation', async () => {
    const h = await fixture();

    h.tx.emailChangeRequest.upsert.mockImplementation(async () => {
      h.config.get.mockReturnValue(undefined);
      return {};
    });

    await expect(
      h.emailChange.request(
        UID,
        SID,
        NEXT,
        PASSWORD
      )
    ).rejects.toThrow(
      'Code delivery was not confirmed. Wait 60 seconds and retry.'
    );

    expect(h.tx.emailChangeRequest.upsert).toHaveBeenCalledOnce();

    expect(h.send).not.toHaveBeenCalled();

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
  });
});
