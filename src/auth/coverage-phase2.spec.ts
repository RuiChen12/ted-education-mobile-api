import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';
import {
  BadRequestException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { createHmac } from 'node:crypto';

import { GoogleAuthService } from './google/google-auth.service';
import { PasswordResetService } from './password/password-reset.service';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SUBJECT = 'google-subject-12345';
const EMAIL = 'patient@example.com';
const CODE = '12345678';
const SECRET = 'test-reset-secret';

function googleHarness() {
  const prisma = {
    socialAccount: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
    user: {
      findUnique: vi.fn().mockResolvedValue(null),
      create: vi.fn(),
    },
  };

  const config = {
    get: vi.fn().mockReturnValue('web-client-id'),
  };

  const mfa = {
    loginResult: vi.fn().mockResolvedValue({
      mfaRequired: false,
      accessToken: 'test-access-token',
    }),
  };

  const service = new GoogleAuthService(
    prisma as never,
    {} as never,
    config as never,
    mfa as never,
  );

  const verify = vi.fn();

  // Mock the private Google client. No network request is sent.
  const client = (
    service as unknown as {
      google: {
        verifyIdToken: typeof verify;
      };
    }
  ).google;

  client.verifyIdToken = verify;

  const validPayload = {
    sub: SUBJECT,
    email: EMAIL,
    email_verified: true,
    name: 'Test Patient',
  };

  function setPayload(
    payload: Record<string, unknown> | undefined,
  ) {
    verify.mockResolvedValue({
      getPayload: () => payload,
    });
  }

  setPayload(validPayload);

  return {
    prisma,
    config,
    mfa,
    service,
    verify,
    setPayload,
    validPayload,
  };
}

const linkedUser = {
  id: USER_ID,
  email: EMAIL,
  isActive: true,
  sessionVersion: 1,
};

describe('Google ID token verification', () => {
  it('rejects an invalid Google token', async () => {
    const h = googleHarness();

    h.verify.mockRejectedValue(
      new Error('Invalid signature'),
    );

    await expect(
      h.service.login('invalid-token'),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.prisma.user.create).not.toHaveBeenCalled();
  });

  it.each([
    ['missing payload', undefined],
    ['missing subject', {
      sub: '',
      email: EMAIL,
      email_verified: true,
    }],
    ['missing email', {
      sub: SUBJECT,
      email: '',
      email_verified: true,
    }],
    ['unverified email', {
      sub: SUBJECT,
      email: EMAIL,
      email_verified: false,
    }],
  ])('rejects %s', async (_name, payload) => {
    const h = googleHarness();

    h.setPayload(payload);

    await expect(
      h.service.login('fake-token'),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.prisma.user.create).not.toHaveBeenCalled();
  });

  it('rejects an excessively long email', async () => {
    const h = googleHarness();

    h.setPayload({
      ...h.validPayload,
      email: 'a'.repeat(250) + '@gmail.com',
    });

    await expect(
      h.service.login('fake-token'),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('uses the configured Google audience', async () => {
    const h = googleHarness();

    h.prisma.socialAccount.findUnique.mockResolvedValue({
      user: linkedUser,
    });

    await h.service.login('google-id-token');

    expect(h.verify).toHaveBeenCalledWith({
      idToken: 'google-id-token',
      audience: 'web-client-id',
    });
  });
});

describe('Google existing account login', () => {
  it('logs in an existing linked account', async () => {
    const h = googleHarness();

    h.prisma.socialAccount.findUnique.mockResolvedValue({
      user: linkedUser,
    });

    const result = await h.service.login('valid-token');

    expect(result).toMatchObject({
      mfaRequired: false,
      accessToken: 'test-access-token',
    });

    expect(h.mfa.loginResult).toHaveBeenCalledWith(
      linkedUser,
    );

    expect(h.prisma.user.create).not.toHaveBeenCalled();
  });

  it('rejects an inactive linked account', async () => {
    const h = googleHarness();

    h.prisma.socialAccount.findUnique.mockResolvedValue({
      user: {
        ...linkedUser,
        isActive: false,
      },
    });

    await expect(
      h.service.login('valid-token'),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.mfa.loginResult).not.toHaveBeenCalled();
  });

  it('refuses to overwrite an existing password account', async () => {
    const h = googleHarness();

    h.prisma.user.findUnique.mockResolvedValue({
      id: USER_ID,
    });

    await expect(
      h.service.login('valid-token'),
    ).rejects.toBeInstanceOf(ConflictException);

    expect(h.prisma.user.create).not.toHaveBeenCalled();
  });
});

describe('Google first-time registration', () => {
  it('creates a Google account with a normalized email', async () => {
    const h = googleHarness();

    h.setPayload({
      ...h.validPayload,
      email: ' PATIENT@GMAIL.COM ',
      name: '  Test   Patient  ',
    });

    h.prisma.user.create.mockResolvedValue(linkedUser);

    await h.service.login('valid-token');

    expect(h.prisma.user.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          email: 'patient@gmail.com',
          fullName: 'Test Patient',
          passwordHash: null,
          role: 'PATIENT',
          emailVerifiedAt: expect.any(Date),
          socialAccounts: {
            create: {
              provider: 'GOOGLE',
              providerUserId: SUBJECT,
            },
          },
        }),
      }),
    );

    expect(h.mfa.loginResult).toHaveBeenCalledWith(
      linkedUser,
    );
  });

  it('uses a fallback name when Google does not supply one', async () => {
    const h = googleHarness();

    h.setPayload({
      ...h.validPayload,
      name: ' ',
      email: 'patient@othermail.com',
    });

    h.prisma.user.create.mockResolvedValue(linkedUser);

    await h.service.login('valid-token');

    expect(h.prisma.user.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          fullName: 'Google User',
          emailVerifiedAt: null,
        }),
      }),
    );
  });

  it('marks a hosted-domain Google account as verified', async () => {
    const h = googleHarness();

    h.setPayload({
      ...h.validPayload,
      email: 'patient@university.edu',
      hd: 'university.edu',
      name: 'Test Patient',
    });

    h.prisma.user.create.mockResolvedValue(linkedUser);

    await h.service.login('valid-token');

    expect(h.prisma.user.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          emailVerifiedAt: expect.any(Date),
        }),
      }),
    );
  });

  it('truncates an overly long Google display name', async () => {
    const h = googleHarness();

    h.setPayload({
      ...h.validPayload,
      name: 'A'.repeat(150),
    });

    h.prisma.user.create.mockResolvedValue(linkedUser);

    await h.service.login('valid-token');

    const call = h.prisma.user.create.mock.calls[0][0];

    expect(call.data.fullName).toHaveLength(120);
  });

  it('recovers from a concurrent account creation', async () => {
    const h = googleHarness();

    h.prisma.socialAccount.findUnique
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({
        user: linkedUser,
      });

    const duplicate = new Prisma.PrismaClientKnownRequestError(
      'Unique constraint failed',
      {
        code: 'P2002',
        clientVersion: '6.19.3',
      },
    );

    h.prisma.user.create.mockRejectedValue(duplicate);

    await expect(
      h.service.login('valid-token'),
    ).resolves.toMatchObject({
      accessToken: 'test-access-token',
    });

    expect(h.mfa.loginResult).toHaveBeenCalledWith(
      linkedUser,
    );
  });

  it('returns conflict when another method owns the email', async () => {
    const h = googleHarness();

    const duplicate = new Prisma.PrismaClientKnownRequestError(
      'Unique constraint failed',
      {
        code: 'P2002',
        clientVersion: '6.19.3',
      },
    );

    h.prisma.user.create.mockRejectedValue(duplicate);

    await expect(
      h.service.login('valid-token'),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('does not hide unrelated database failures', async () => {
    const h = googleHarness();

    const failure = new Error('Database unavailable');

    h.prisma.user.create.mockRejectedValue(failure);

    await expect(
      h.service.login('valid-token'),
    ).rejects.toBe(failure);
  });
});

function resetHarness() {
  const user = { id: USER_ID, email: EMAIL, isActive: true, passwordHash: 'old-hash', sessionVersion: 3, emailVerifiedAt: new Date(), preferredLanguage: 'en', passwordResetSentInWindow: 0, passwordResetWindowStartedAt: null, passwordResetLastSentAt: null };
  const tx = {
    $queryRaw: vi.fn().mockResolvedValue([]),
    user: { findUnique: vi.fn().mockResolvedValue(user), update: vi.fn().mockResolvedValue({}), updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    passwordResetCode: { findUnique: vi.fn().mockResolvedValue(null), upsert: vi.fn().mockResolvedValue({}), updateMany: vi.fn().mockResolvedValue({ count: 1 }), deleteMany: vi.fn().mockResolvedValue({ count: 1 }) },
    authSession: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    emailChangeRequest: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    emailVerificationCode: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    googleActionChallenge: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    securityEvent: { create: vi.fn().mockResolvedValue({}) },
    securityNotification: { create: vi.fn().mockResolvedValue({}) },
  };
  const prisma = { ...tx, user: { ...tx.user, findUnique: vi.fn().mockResolvedValue(null) }, $transaction: vi.fn(async (fn: (client: typeof tx) => Promise<unknown>) => fn(tx)) };
  const config = { get: vi.fn((name: string) => name === 'RESEND_API_KEY' ? 'test-api-key' : name === 'RESET_EMAIL_FROM' ? 'test@example.com' : undefined), getOrThrow: vi.fn().mockReturnValue(SECRET) };
  const service = new PasswordResetService(prisma as never, config as never);
  return { prisma, config, service, user, tx };
}

function mockFetch(
  result: { ok: boolean; status: number } = {
    ok: true,
    status: 200,
  },
) {
  const fetchMock = vi.fn().mockResolvedValue(result);

  vi.stubGlobal('fetch', fetchMock);

  return fetchMock;
}

function prepareValidReset() {
  const h = resetHarness();
  const codeHash = createHmac('sha256', SECRET)
    .update(JSON.stringify(['ted:reset:v2', USER_ID, EMAIL, h.user.sessionVersion, CODE])).digest('hex');
  h.prisma.user.findUnique.mockResolvedValue(h.user);
  h.prisma.passwordResetCode.findUnique.mockResolvedValue({ codeHash, attempts: 0, sentAt: new Date(Date.now() - 1000), expiresAt: new Date(Date.now() + 600000) });
  return h;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Password reset code delivery', () => {
  it('does not send mail to an inactive account', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);
    h.tx.user.findUnique.mockResolvedValue({ ...h.user, isActive: false });

    const fetchMock = mockFetch();

    const result = await h.service.requestCode(EMAIL);

    expect(result.message).toContain('If an eligible account exists');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('enforces the 60-second resend cooldown', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    h.prisma.passwordResetCode.findUnique.mockResolvedValue({
      sentAt: new Date(),
    });

    const fetchMock = mockFetch();

    await h.service.requestCode(EMAIL);

    expect(h.prisma.passwordResetCode.upsert)
      .not.toHaveBeenCalled();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('generates and stores a hashed expiring reset code', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    const fetchMock = mockFetch();

    const result = await h.service.requestCode(
      '  PATIENT@EXAMPLE.COM  ',
    );

    expect(result.message).toContain('If an eligible account exists');

    const call = h.prisma.passwordResetCode.upsert.mock.calls[0][0];

    expect(call.create.codeHash).toMatch(/^[a-f0-9]{64}$/);
    expect(call.create.attempts).toBe(0);

    const duration =
      call.create.expiresAt.getTime() -
      call.create.sentAt.getTime();

    expect(duration).toBe(600000);

    const body = JSON.parse(
      fetchMock.mock.calls[0][1].body,
    );

    expect(body.to).toEqual([EMAIL]);
    expect(body.text).toMatch(/\b\d{8}\b/);
  });

  it('replaces an older reset code', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    h.prisma.passwordResetCode.findUnique.mockResolvedValue({
      sentAt: new Date(Date.now() - 120000),
    });

    mockFetch();

    await h.service.requestCode(EMAIL);

    expect(h.prisma.passwordResetCode.upsert)
      .toHaveBeenCalledOnce();
  });

  it('invalidates the undelivered code without deleting quota', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    mockFetch({
      ok: false,
      status: 403,
    });

    const result = await h.service.requestCode(EMAIL);

    expect(result.message).toContain('If an eligible account exists');

    expect(h.prisma.passwordResetCode.updateMany)
      .toHaveBeenCalledWith(expect.objectContaining({ data: { expiresAt: expect.any(Date), attempts: 5 } }));
  });

  it('handles a mail network failure without exposing the user', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Network failure')),
    );

    await expect(
      h.service.requestCode(EMAIL),
    ).resolves.toHaveProperty('message');

    expect(h.prisma.passwordResetCode.updateMany)
      .toHaveBeenCalledWith(expect.objectContaining({ data: { expiresAt: expect.any(Date), attempts: 5 } }));
  });
});

describe('Password reset validation and consumption', () => {
  it('rejects a missing reset-code record', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    await expect(
      h.service.resetPassword(
        EMAIL,
        CODE,
        'NewPassword123!',
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects an invalid hash length', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    h.prisma.passwordResetCode.findUnique.mockResolvedValue({
      codeHash: '1234',
      attempts: 0,
      expiresAt: new Date(Date.now() + 600000),
    });

    await expect(
      h.service.resetPassword(
        EMAIL,
        CODE,
        'NewPassword123!',
      ),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.prisma.passwordResetCode.updateMany)
      .toHaveBeenCalledWith(expect.objectContaining({ data: { attempts: { increment: 1 } } }));
  });

  it('rejects reuse of a consumed reset code', async () => {
    const h = prepareValidReset();

    h.tx.passwordResetCode.deleteMany.mockResolvedValue({
      count: 0,
    });

    await expect(
      h.service.resetPassword(
        EMAIL,
        CODE,
        'NewPassword123!',
      ),
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
  });

  it('changes the password and invalidates old sessions', async () => {
    const h = prepareValidReset();

    const fetchMock = mockFetch();

    const result = await h.service.resetPassword(
      '  PATIENT@EXAMPLE.COM ',
      CODE,
      'NewPassword123!',
    );

    expect(result).toEqual({
      message: 'Password changed. Sign in again.',
    });

    expect(h.tx.passwordResetCode.deleteMany)
      .toHaveBeenCalledOnce();

    expect(h.tx.user.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ id: USER_ID, email: EMAIL, sessionVersion: 3, passwordHash: h.user.passwordHash }),
        data: expect.objectContaining({
          passwordHash: expect.any(String),
          sessionVersion: { increment: 1 },
        }),
      }),
    );

    expect(fetchMock).not.toHaveBeenCalled();
    expect(h.tx.authSession.updateMany).toHaveBeenCalledWith({ where: { userId: USER_ID, revokedAt: null }, data: { revokedAt: expect.any(Date) } });
    expect(h.tx.securityNotification.create).toHaveBeenCalledWith({ data: { userId: USER_ID, recipient: EMAIL, kind: 'PASSWORD_RESET', language: 'en' } });
  });

  it('succeeds even if the notification email is unavailable', async () => {
    const h = prepareValidReset();

    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(
        new Error('Email service unavailable'),
      ),
    );

    await expect(
      h.service.resetPassword(
        EMAIL,
        CODE,
        'NewPassword123!',
      ),
    ).resolves.toHaveProperty(
      'message',
      'Password changed. Sign in again.',
    );

    expect(h.tx.user.updateMany).toHaveBeenCalledOnce();
  });

  it('does not require mail settings to finish a password change', async () => {
    const h = prepareValidReset();

    h.config.get.mockReturnValue(undefined);

    const fetchMock = mockFetch();

    await expect(
      h.service.resetPassword(
        EMAIL,
        CODE,
        'NewPassword123!',
      ),
    ).resolves.toHaveProperty('message');

    expect(fetchMock).not.toHaveBeenCalled();

    expect(h.tx.user.updateMany).toHaveBeenCalledOnce();
  });

  it('does not fail when notification provider returns HTTP 500', async () => {
    const h = prepareValidReset();

    mockFetch({
      ok: false,
      status: 500,
    });

    await expect(
      h.service.resetPassword(
        EMAIL,
        CODE,
        'NewPassword123!',
      ),
    ).resolves.toHaveProperty('message');
  });
});


describe('Coverage phase 3 remaining edge cases', () => {

  it('uses a fallback name when Google omits the name field', async () => {
    const h = googleHarness();

    h.setPayload({
      sub: SUBJECT,
      email: EMAIL,
      email_verified: true,
    });

    h.prisma.user.create.mockResolvedValue(linkedUser);

    await h.service.login('valid-token');

    expect(h.prisma.user.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          fullName: 'Google User',
        }),
      }),
    );
  });

  it('survives failure when invalidating an undelivered reset code', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    h.prisma.passwordResetCode.updateMany.mockRejectedValue(
      new Error('Cleanup unavailable'),
    );

    mockFetch({
      ok: false,
      status: 403,
    });

    await expect(
      h.service.requestCode(EMAIL),
    ).resolves.toHaveProperty('message');

    expect(h.prisma.passwordResetCode.updateMany)
      .toHaveBeenCalledWith(expect.objectContaining({ data: { expiresAt: expect.any(Date), attempts: 5 } }));
  });

  it('handles non-Error exceptions from the email transport', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue('transport unavailable'),
    );

    await expect(
      h.service.requestCode(EMAIL),
    ).resolves.toHaveProperty('message');

    expect(h.prisma.passwordResetCode.updateMany)
      .toHaveBeenCalledWith(expect.objectContaining({ data: { expiresAt: expect.any(Date), attempts: 5 } }));
  });
});

// Final coverage closeout

describe('Final password reset quota and concurrency boundaries', () => {
  it.each([2, 5])(
    'preserves account-level hourly quota with %s sends',
    async count => {
      const h = resetHarness();
      const started = new Date(Date.now() - 180000);

      h.prisma.user.findUnique.mockResolvedValue(h.user);

      h.tx.user.findUnique.mockResolvedValue({
        ...h.user,
        passwordResetWindowStartedAt: started,
        passwordResetSentInWindow: count,
        passwordResetLastSentAt: new Date(Date.now() - 120000)
      });

      const send = mockFetch();

      await h.service.requestCode(EMAIL);

      if (count === 5) {
        expect(send).not.toHaveBeenCalled();
        expect(h.tx.passwordResetCode.upsert).not.toHaveBeenCalled();
      } else {
        expect(send).toHaveBeenCalledOnce();

        expect(h.tx.user.update).toHaveBeenCalledWith(
          expect.objectContaining({
            data: expect.objectContaining({
              passwordResetSentInWindow: count + 1,
              passwordResetWindowStartedAt: started
            })
          })
        );
      }
    }
  );

  it('does not invalidate proof after an undelivered request loses its owner', async () => {
    const h = resetHarness();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    h.tx.user.findUnique
      .mockResolvedValueOnce(h.user)
      .mockResolvedValueOnce(null);

    mockFetch({ ok: false, status: 500 });

    await expect(h.service.requestCode(EMAIL))
      .resolves.toHaveProperty('message');

    expect(h.tx.passwordResetCode.updateMany).not.toHaveBeenCalled();
  });

  it('rejects malformed reset proof before account lookup', async () => {
    const h = resetHarness();

    await expect(h.service.resetPassword(
      EMAIL, 'invalid', 'NewPassword123!'
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.prisma.user.findUnique).not.toHaveBeenCalled();
  });

  it('rejects reset after account disappearance', async () => {
    const h = prepareValidReset();

    h.prisma.user.findUnique.mockResolvedValue(h.user);
    h.tx.user.findUnique.mockResolvedValue(null);

    await expect(h.service.resetPassword(
      EMAIL, CODE, 'NewPassword123!'
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
  });

  it('rejects a changed account between proof validation and password commit', async () => {
    const h = prepareValidReset();

    h.prisma.user.findUnique.mockResolvedValue(h.user);

    h.tx.user.findUnique
      .mockResolvedValueOnce(h.user)
      .mockResolvedValueOnce({
        ...h.user, sessionVersion: h.user.sessionVersion + 1
      });

    await expect(h.service.resetPassword(
      EMAIL, CODE, 'NewPassword123!'
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
  });

  it('rejects lost password-reset compare-and-set', async () => {
    const h = prepareValidReset();

    h.prisma.user.findUnique.mockResolvedValue(h.user);
    h.tx.user.updateMany.mockResolvedValue({ count: 0 });

    await expect(h.service.resetPassword(
      EMAIL, CODE, 'NewPassword123!'
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.authSession.updateMany).not.toHaveBeenCalled();
    expect(h.tx.securityNotification.create).not.toHaveBeenCalled();
  });
});
