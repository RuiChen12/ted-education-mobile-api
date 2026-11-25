import { recordLimitedSecurityEvent } from '../security/security-activity.service';
import { enqueueSecurityNotification } from '../../notifications/security-notification.service';
import {
  BadRequestException, ConflictException, Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { Prisma, MfaSetting } from '@prisma/client';
import {
  createCipheriv, createDecipheriv, createHmac,
  randomBytes, randomUUID, timingSafeEqual,
} from 'node:crypto';
import { AuthSessionService } from '../sessions/auth-session.service';
import { PrismaService } from '../../prisma/prisma.service';
import {
  JWT_ALGORITHM, JWT_AUDIENCE, JWT_ISSUER,
  UUID_V4_PATTERN,
} from '../jwt/jwt.config';

function base32Encode(bytes: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  // A 20-byte secret contains exactly 32 Base32 symbols; no remainder.
  return out;
}

function base32Decode(text: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of text.replace(/=+$/, '').toUpperCase()) {
    const n = alphabet.indexOf(c);
    if (n === -1) throw new Error('Invalid TOTP secret');
    value = (value << 5) | n;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function totpStep(secret: string, code: string, lastUsed: number): number | null {
  if (!/^[0-9]{6}$/.test(code)) return null;
  const key = base32Decode(secret);
  const current = Math.floor(Date.now() / 30000);
  for (const step of [current, current - 1, current + 1]) {
    if (step <= lastUsed) continue;
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(step));
    const digest = createHmac('sha1', key).update(counter).digest();
    const offset = digest[digest.length - 1] & 15;
    const value = (digest.readUInt32BE(offset) & 0x7fffffff) % 1000000;
    const expected = Buffer.from(String(value).padStart(6, '0'));
    if (timingSafeEqual(expected, Buffer.from(code))) return step;
  }
  return null;
}

@Injectable()
export class MfaService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly sessions: AuthSessionService,
  ) {}

  private key(): Buffer {
    const hex = this.config.getOrThrow<string>('MFA_ENCRYPTION_KEY');
    if (!/^[0-9a-f]{64}$/i.test(hex)) {
      throw new Error('MFA_ENCRYPTION_KEY must be 64 hex characters');
    }
    return Buffer.from(hex, 'hex');
  }

  private encrypt(clear: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key(), iv);
    const data = Buffer.concat([cipher.update(clear, 'utf8'), cipher.final()]);
    return [iv, cipher.getAuthTag(), data].map(x => x.toString('base64url')).join('.');
  }

  private decrypt(value: string): string {
    const [i, t, d] = value.split('.');
    if (!i || !t || !d) throw new Error('Invalid encrypted secret');
    const decipher = createDecipheriv('aes-256-gcm', this.key(), Buffer.from(i, 'base64url'));
    decipher.setAuthTag(Buffer.from(t, 'base64url'));
    return Buffer.concat([
      decipher.update(Buffer.from(d, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  }


  private recoveryHash(code: string): string {
    return createHmac('sha256', this.key())
      .update('ted-mfa-recovery:' + code.replace(/-/g, '').toUpperCase())
      .digest('hex');
  }


  async loginResult(user: { id: string; sessionVersion: number }) {
    return this.prisma.$transaction(async tx => {
      const current = await this.lockMfaUser(
        tx,
        user.id,
      );

      if (
        current.sessionVersion !== user.sessionVersion
      ) {
        throw new UnauthorizedException(
          'Sign in again.',
        );
      }

      const factor = await tx.mfaSetting.findUnique({
        where: { userId: user.id },
        select: { enabledAt: true },
      });

      if (!factor?.enabledAt) {
        await tx.mfaLoginChallenge.deleteMany({
          where: { userId: user.id },
        });

        return this.sessions.issueInTransaction(
          tx,
          user.id,
          current.sessionVersion,
        );
      }

      const challengeId = randomUUID();

      const expiresAt = new Date(
        Date.now() + 5 * 60 * 1000,
      );

      const challengeToken = await this.jwt.signAsync(
        {
          sub: user.id,
          purpose: 'mfa',
          sv: current.sessionVersion,
          jti: challengeId,
        },
        { expiresIn: '5m' },
      );

      await tx.mfaLoginChallenge.upsert({
        where: { userId: user.id },
        create: {
          userId: user.id,
          challengeId,
          sessionVersion: current.sessionVersion,
          expiresAt,
        },
        update: {
          challengeId,
          sessionVersion: current.sessionVersion,
          expiresAt,
          createdAt: new Date(),
        },
      });

      return {
        mfaRequired: true as const,
        challengeToken,
      };
    });
  }

  async status(userId: string) {
    const factor = await this.prisma.mfaSetting.findUnique({
      where: { userId }, select: { enabledAt: true, recoveryHashes: true },
    });
    return { enabled: Boolean(factor?.enabledAt), recoveryCodesRemaining: factor?.enabledAt ? factor.recoveryHashes.length : 0 };
  }

  private async lockMfaUser(
    tx: Prisma.TransactionClient,
    userId: string,
  ) {
    if (!UUID_V4_PATTERN.test(userId)) {
      throw new UnauthorizedException('Sign in again.');
    }

    await tx.$queryRaw`
      SELECT "id"
      FROM "User"
      WHERE "id" = ${userId}::uuid
      FOR UPDATE
    `;

    const user = await tx.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        isActive: true,
        passwordHash: true,
        emailVerifiedAt: true,
        sessionVersion: true,
      },
    });

    if (
      !user?.isActive ||
      (user.passwordHash && !user.emailVerifiedAt)
    ) {
      throw new UnauthorizedException('Sign in again.');
    }

    return user;
  }

  private async requireMfaSession(
    tx: Prisma.TransactionClient,
    userId: string,
    sessionId: string,
    version: number,
  ) {
    if (!UUID_V4_PATTERN.test(sessionId)) {
      throw new UnauthorizedException('Sign in again.');
    }

    await tx.$queryRaw`
      SELECT "id"
      FROM "AuthSession"
      WHERE "id" = ${sessionId}::uuid
        AND "userId" = ${userId}::uuid
      FOR UPDATE
    `;

    const now = new Date();

    const session = await tx.authSession.findFirst({
      where: {
        id: sessionId,
        userId,
        sessionVersion: version,
        revokedAt: null,
        expiresAt: { gt: now },
        absoluteExpiresAt: { gt: now },
      },
      select: { id: true },
    });

    if (!session) {
      throw new UnauthorizedException(
        'Session expired. Sign in again.',
      );
    }
  }

  private effectiveAttempts(
    factor: MfaSetting,
    now: Date,
  ) {
    if (
      factor.lockedUntil &&
      factor.lockedUntil <= now
    ) {
      return 0;
    }

    return factor.attempts;
  }

  private isLocked(
    factor: MfaSetting,
    now: Date,
  ) {
    return Boolean(
      (factor.lockedUntil && factor.lockedUntil > now) ||
      this.effectiveAttempts(factor, now) >= 5
    );
  }

  private async recordFactorFailure(
    tx: Prisma.TransactionClient,
    factor: MfaSetting,
    now: Date,
  ) {
    const attempts = Math.min(
      this.effectiveAttempts(factor, now) + 1,
      5,
    );

    await tx.mfaSetting.update({
      where: { userId: factor.userId },
      data: {
        attempts,
        lockedUntil: attempts >= 5
          ? new Date(now.getTime() + 15 * 60_000)
          : null,
      },
    });

    await recordLimitedSecurityEvent(
      tx,
      factor.userId,
      'MFA_VERIFICATION_FAILED',
      now,
    );
  }

  private createRecoveryCodes() {
    const codes = Array.from({ length: 8 }, () => {
      const raw = randomBytes(8)
        .toString('hex')
        .toUpperCase();

      return raw.slice(0, 8) + '-' + raw.slice(8);
    });

    return {
      codes,
      hashes: codes.map(code => this.recoveryHash(code)),
    };
  }

  async setup(
    userId: string,
    sessionId: string,
  ) {
    return this.prisma.$transaction(async tx => {
      const user = await this.lockMfaUser(tx, userId);

      await this.requireMfaSession(
        tx,
        userId,
        sessionId,
        user.sessionVersion,
      );

      const existing = await tx.mfaSetting.findUnique({
        where: { userId },
      });

      if (existing?.enabledAt) {
        throw new ConflictException(
          'Two-factor authentication is already enabled.',
        );
      }

      const now = new Date();

      if (existing && this.isLocked(existing, now)) {
        throw new BadRequestException(
          'Too many attempts. Try again later.',
        );
      }

      const secret = base32Encode(randomBytes(20));

      // Bind the pending secret to the current account,
      // authenticated session and account version.
      const pendingCipher = this.encrypt(
        JSON.stringify([
          'ted:mfa-setup:v2',
          userId,
          sessionId,
          user.sessionVersion,
          secret,
        ]),
      );

      const attempts = existing
        ? this.effectiveAttempts(existing, now)
        : 0;

      await tx.mfaSetting.upsert({
        where: { userId },
        create: {
          userId,
          pendingCipher,
          pendingAt: now,
        },
        update: {
          pendingCipher,
          pendingAt: now,
          attempts,
          lockedUntil: null,
        },
      });

      const label = encodeURIComponent(
        'TED Education:' + user.email,
      );

      const uri =
        'otpauth://totp/' + label +
        '?secret=' + secret +
        '&issuer=TED%20Education' +
        '&algorithm=SHA1&digits=6&period=30';

      return { secret, uri };
    });
  }

  private readPendingSecret(
    cipher: string,
    userId: string,
    sessionId: string,
    version: number,
  ): string {
    let value: unknown;

    try {
      value = JSON.parse(this.decrypt(cipher));
    } catch {
      throw new BadRequestException(
        'Setup expired. Start again.',
      );
    }

    if (
      !Array.isArray(value) ||
      value.length !== 5 ||
      value[0] !== 'ted:mfa-setup:v2' ||
      value[1] !== userId ||
      value[2] !== sessionId ||
      value[3] !== version ||
      typeof value[4] !== 'string' ||
      !/^[A-Z2-7]{32}$/.test(value[4])
    ) {
      throw new BadRequestException(
        'Setup expired or belongs to another session. Start again.',
      );
    }

    return value[4];
  }

  private async rotateMfaSessions(
    tx: Prisma.TransactionClient,
    userId: string,
    version: number,
    event: 'MFA_ENABLED' | 'MFA_DISABLED',
  ) {
    const now = new Date();

    const changed = await tx.user.updateMany({
      where: {
        id: userId,
        isActive: true,
        sessionVersion: version,
      },
      data: {
        sessionVersion: { increment: 1 },
      },
    });

    if (changed.count !== 1) {
      throw new ConflictException(
        'Account changed. Sign in again.',
      );
    }

    await tx.authSession.updateMany({
      where: {
        userId,
        revokedAt: null,
      },
      data: { revokedAt: now },
    });

    await tx.passwordResetCode.deleteMany({
      where: { userId },
    });

    await tx.emailChangeRequest.updateMany({
          where: { userId },
          data: { attempts: 5 },
        });

    // Invalidate pending Google-sensitive actions while
    // preserving their server-side rate-limit history.
    await tx.googleActionChallenge.updateMany({
      where: {
        userId,
        consumedAt: null,
      },
      data: { consumedAt: now },
    });

    await tx.securityEvent.create({
      data: {
        userId,
        type: event,
      },
    });

    await enqueueSecurityNotification(tx, userId, event);

    return this.sessions.issueInTransaction(
      tx,
      userId,
      version + 1,
    );
  }

  async enable(
    userId: string,
    code: string,
    sessionId: string,
  ) {
    const result = await this.prisma.$transaction(
      async tx => {
        const user = await this.lockMfaUser(tx, userId);

        await this.requireMfaSession(
          tx,
          userId,
          sessionId,
          user.sessionVersion,
        );

        const factor = await tx.mfaSetting.findUnique({
          where: { userId },
        });

        const now = new Date();

        if (
          !factor ||
          factor.enabledAt ||
          !factor.pendingCipher ||
          !factor.pendingAt ||
          factor.pendingAt > now ||
          now.getTime() - factor.pendingAt.getTime() >= 600000
        ) {
          throw new BadRequestException(
            'Setup expired. Start again.',
          );
        }

        if (this.isLocked(factor, now)) {
          return null;
        }

        const secret = this.readPendingSecret(
          factor.pendingCipher,
          userId,
          sessionId,
          user.sessionVersion,
        );

        const step = totpStep(secret, code, -1);

        if (step === null) {
          await this.recordFactorFailure(
            tx,
            factor,
            now,
          );

          // Commit failed attempts.
          return null;
        }

        const recovery = this.createRecoveryCodes();

        const updated = await tx.mfaSetting.updateMany({
          where: {
            userId,
            enabledAt: null,
            pendingCipher: factor.pendingCipher,
          },
          data: {
            secretCipher: this.encrypt(secret),
            pendingCipher: null,
            pendingAt: null,
            enabledAt: now,
            lastUsedStep: step,
            recoveryHashes: recovery.hashes,
            attempts: 0,
            lockedUntil: null,
          },
        });

        if (updated.count !== 1) {
          throw new ConflictException(
            'Setup changed. Try again.',
          );
        }

        const session = await this.rotateMfaSessions(
          tx,
          userId,
          user.sessionVersion,
          'MFA_ENABLED',
        );

        return {
          ...session,
          recoveryCodes: recovery.codes,
        };
      },
    );

    if (!result) {
      throw new BadRequestException(
        'Invalid or unavailable authenticator code.',
      );
    }


    return result;
  }

  // Caller must hold the User lock.
  // All factor writes are performed in this transaction.

  private async consumeFactor(
    tx: Prisma.TransactionClient,
    userId: string,
    code: string,
    allowRecovery: boolean,
  ): Promise<boolean> {
    const factor = await tx.mfaSetting.findUnique({
      where: { userId },
    });

    const now = new Date();

    if (
      !factor?.enabledAt ||
      !factor.secretCipher ||
      this.isLocked(factor, now)
    ) {
      return false;
    }

    const clean = code.trim().toUpperCase();

    if (/^[0-9]{6}$/.test(clean)) {
      const step = totpStep(
        this.decrypt(factor.secretCipher),
        clean,
        factor.lastUsedStep,
      );

      if (step !== null) {
        const changed = await tx.mfaSetting.updateMany({
          where: {
            userId,
            enabledAt: { not: null },
            secretCipher: factor.secretCipher,
            lastUsedStep: { lt: step },
          },
          data: {
            lastUsedStep: step,
            attempts: 0,
            lockedUntil: null,
          },
        });

        if (changed.count === 1) {
          return true;
        }

        return false;
      }
    } else if (
      allowRecovery &&
      /^[0-9A-F]{8}-[0-9A-F]{8}$/.test(clean)
    ) {
      const digest = this.recoveryHash(clean);

      const matches = factor.recoveryHashes.some(value =>
        /^[a-f0-9]{64}$/i.test(value) &&
        timingSafeEqual(
          Buffer.from(value, 'hex'),
          Buffer.from(digest, 'hex'),
        ),
      );

      if (matches) {
        await tx.mfaSetting.update({
          where: { userId },
          data: {
            recoveryHashes: factor.recoveryHashes.filter(
              value => value !== digest,
            ),
            attempts: 0,
            lockedUntil: null,
          },
        });

        return true;
      }
    }

    await this.recordFactorFailure(
      tx,
      factor,
      now,
    );

    return false;
  }

  // Caller must hold the User row lock.
  private async verifyEnabledFactor(
    tx: Prisma.TransactionClient,
    userId: string,
    code?: string,
  ): Promise<boolean> {
    const factor = await tx.mfaSetting.findUnique({
      where: { userId },
      select: {
        enabledAt: true,
      },
    });

    if (!factor?.enabledAt) {
      return true;
    }

    if (
      typeof code !== 'string' ||
      code.length !== 6 ||
      !/^[0-9]{6}$/.test(code)
    ) {
      return false;
    }

    return this.consumeFactor(
      tx,
      userId,
      code,
      false,
    );
  }

  /**
   * Verify MFA inside the transaction performing
   * the sensitive account operation.
   *
   * Lock order: User -> AuthSession -> MFA.
   *
   * A false result must be returned from the enclosing
   * transaction without performing the sensitive operation.
   * Throw the authentication error after commit so that
   * failed-attempt counters are preserved.
   */
  async verifySensitiveActionInTransaction(
    tx: Prisma.TransactionClient,
    userId: string,
    sessionId: string,
    expectedVersion: number,
    code?: string,
  ): Promise<boolean> {
    if (
      !Number.isInteger(expectedVersion) ||
      expectedVersion < 0 ||
      expectedVersion > 2147483647
    ) {
      throw new UnauthorizedException(
        'Sign in again.',
      );
    }

    const user = await this.lockMfaUser(
      tx,
      userId,
    );

    if (
      user.sessionVersion !== expectedVersion
    ) {
      throw new UnauthorizedException(
        'Account security settings changed. Sign in again.',
      );
    }

    await this.requireMfaSession(
      tx,
      userId,
      sessionId,
      expectedVersion,
    );

    return this.verifyEnabledFactor(
      tx,
      userId,
      code,
    );
  }

  /**
   * Compatibility method for existing callers.
   * Sensitive operations should migrate to
   * verifySensitiveActionInTransaction.
   */
  async verifySensitiveAction(
    userId: string,
    code?: string,
  ): Promise<void> {
    const valid = await this.prisma.$transaction(
      async tx => {
        await this.lockMfaUser(tx, userId);

        return this.verifyEnabledFactor(
          tx,
          userId,
          code,
        );
      },
    );

    if (!valid) {
      throw new BadRequestException(
        'A valid current authenticator code is required.',
      );
    }
  }

  async verifyChallenge(
    challengeToken: string,
    code: string,
  ) {
    let payload: {
      sub?: string;
      purpose?: string;
      jti?: string;
      sv?: number;
      exp?: number;
    };

    try {
      payload = await this.jwt.verifyAsync(
        challengeToken,
        {
          algorithms: [JWT_ALGORITHM],
          issuer: JWT_ISSUER,
          audience: JWT_AUDIENCE,
        },
      );
    } catch {
      throw new UnauthorizedException(
        'Sign in again. Verification expired.',
      );
    }

    const userId = payload.sub;
    const version = payload.sv;
    const expiration = payload.exp;
    const challengeId = payload.jti;

    if (
      typeof userId !== 'string' ||
      !UUID_V4_PATTERN.test(userId) ||
      payload.purpose !== 'mfa' ||
      typeof challengeId !== 'string' ||
      !UUID_V4_PATTERN.test(challengeId) ||
      typeof version !== 'number' ||
      !Number.isInteger(version) ||
      version < 0 ||
      version > 2147483647 ||
      typeof expiration !== 'number' ||
      !Number.isInteger(expiration) ||
      expiration <= Math.floor(Date.now() / 1000)
    ) {
      throw new UnauthorizedException(
        'Invalid verification challenge.',
      );
    }

    const result = await this.prisma.$transaction(
      async tx => {
        const user = await this.lockMfaUser(
          tx,
          userId,
        );

        if (
          user.sessionVersion !== version ||
          expiration <= Math.floor(Date.now() / 1000)
        ) {
          throw new UnauthorizedException(
            'Sign in again.',
          );
        }

        const challenge =
          await tx.mfaLoginChallenge.findFirst({
            where: {
              userId,
              challengeId,
              sessionVersion: version,
              expiresAt: { gt: new Date() },
            },
            select: {
              challengeId: true,
            },
          });

        if (!challenge) {
          throw new UnauthorizedException(
            'Sign in again. Verification expired.',
          );
        }

        const valid = await this.consumeFactor(
          tx,
          userId,
          code,
          true,
        );

        if (!valid) {
          return null;
        }

        const consumed =
          await tx.mfaLoginChallenge.deleteMany({
            where: {
              userId,
              challengeId,
              sessionVersion: version,
              expiresAt: { gt: new Date() },
            },
          });

        if (consumed.count !== 1) {
          throw new UnauthorizedException(
            'Sign in again. Verification expired.',
          );
        }

        return this.sessions.issueInTransaction(
          tx,
          userId,
          version,
        );
      },
    );

    if (!result) {
      throw new UnauthorizedException(
        'Invalid or unavailable verification code.',
      );
    }

    return result;
  }

  async regenerateRecoveryCodes(
    userId: string,
    code: string,
    sessionId: string,
  ) {
    if (!/^[0-9]{6}$/.test(code)) {
      throw new BadRequestException(
        'Authenticator code required.',
      );
    }

    const result = await this.prisma.$transaction(
      async tx => {
        const user = await this.lockMfaUser(
          tx,
          userId,
        );

        await this.requireMfaSession(
          tx,
          userId,
          sessionId,
          user.sessionVersion,
        );

        const valid = await this.consumeFactor(
          tx,
          userId,
          code,
          false,
        );

        if (!valid) return null;

        const recovery = this.createRecoveryCodes();

        await tx.mfaSetting.update({
          where: { userId },
          data: {
            recoveryHashes: recovery.hashes,
          },
        });

        await tx.securityEvent.create({
          data: {
            userId,
            type: 'RECOVERY_CODES_REGENERATED',
          },
        });

        await enqueueSecurityNotification(tx, userId, 'RECOVERY_CODES_REGENERATED');

        return {
          recoveryCodes: recovery.codes,
          recoveryCodesRemaining: recovery.codes.length,
        };
      },
    );

    if (!result) {
      throw new BadRequestException(
        'Invalid or unavailable authenticator code.',
      );
    }

    return result;
  }

  async disable(
    userId: string,
    code: string,
    sessionId: string,
  ) {
    const result = await this.prisma.$transaction(
      async tx => {
        const user = await this.lockMfaUser(
          tx,
          userId,
        );

        await this.requireMfaSession(
          tx,
          userId,
          sessionId,
          user.sessionVersion,
        );

        const valid = await this.consumeFactor(
          tx,
          userId,
          code,
          true,
        );

        if (!valid) return null;

        const removed = await tx.mfaSetting.deleteMany({
          where: {
            userId,
            enabledAt: { not: null },
          },
        });

        if (removed.count !== 1) {
          throw new ConflictException(
            'Two-factor authentication changed.',
          );
        }

        return this.rotateMfaSessions(
          tx,
          userId,
          user.sessionVersion,
          'MFA_DISABLED',
        );
      },
    );

    if (!result) {
      throw new BadRequestException(
        'Invalid or unavailable verification code.',
      );
    }


    return result;
  }
}
