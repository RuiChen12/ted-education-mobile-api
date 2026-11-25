import { Prisma as CloseoutPrisma } from '@prisma/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { hash } from 'bcryptjs';
import { AccountDataService } from './account/account-data.service';
import { ConnectedAccountsService } from './account/connected-accounts.service';
import { EmailChangeController } from './email/email-change.controller';
import { AuthSessionService } from './sessions/auth-session.service';
import { parseActivityCursor, recordLimitedSecurityEvent } from './security/security-activity.service';
import { SecurityLifecycleService } from './security/security-lifecycle.service';
import { PostgresRateLimitStorage } from '../common/config/postgres-rate-limit.storage';
import { SecurityNotificationService, enqueueSecurityNotification } from '../notifications/security-notification.service';
import { createHash, createHmac } from 'node:crypto';
import { GoogleActionChallengeService } from './google/google-action-challenge.service';
import { EmailChangeService } from './email/email-change.service';

const UID = '11111111-1111-4111-8111-111111111111';
const SID = '22222222-2222-4222-8222-222222222222';
const RID = '33333333-3333-4333-8333-333333333333';
const EMAIL = 'patient@example.test';
const PASSWORD = 'test-only-password-123';
const REQ = { user: { id: UID }, sessionId: SID };

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

async function accountHarness() {
  const user = { id: UID, email: EMAIL, role: 'PATIENT', isActive: true, passwordHash: await hash(PASSWORD, 4), sessionVersion: 4, emailVerifiedAt: new Date() };
  const now = new Date();
  const profile = { id: UID, email: EMAIL, fullName: 'Test Patient', gender: null, role: 'PATIENT', preferredLanguage: 'en', fontScale: 1, highContrast: false, onboardingStep: 3, onboardingCompletedAt: now, emailVerifiedAt: now, createdAt: now, updatedAt: now, socialAccounts: [], mfaSetting: null };
  const session = { createdAt: now, updatedAt: now, expiresAt: now, absoluteExpiresAt: now, revokedAt: null, devicePlatform: 'android', lastActiveAt: now };
  const tx = {
    $queryRaw: vi.fn().mockResolvedValue([]),
    user: {
      findFirst: vi.fn().mockResolvedValue(profile),
      delete: vi.fn().mockResolvedValue({})
    },
    authSession: {
      findFirst: vi.fn().mockResolvedValue({ id: SID }),
      findMany: vi.fn().mockResolvedValue(Array.from({length:201}, () => session))
    },
    securityEvent: {
      findMany: vi.fn().mockResolvedValue(Array.from({length:1001}, () => ({ type: 'SESSION_CREATED', createdAt: now })))
    },
    avatarCleanupJob: {
      upsert: vi.fn().mockResolvedValue({})
    }
  };

  const prisma = {
    user: { findUnique: vi.fn().mockResolvedValue(user) },
    $transaction: vi.fn(async (fn: (client: typeof tx) => Promise<unknown>) => fn(tx))
  };

  const mfa = {
    verifySensitiveActionInTransaction: vi.fn().mockResolvedValue(true)
  };

  const google = {
    request: vi.fn().mockResolvedValue({requestId:RID}),
    execute: vi.fn()
  };

  const service = new AccountDataService(prisma as never, mfa as never, google as never);

  return { user, profile, tx, prisma, mfa, google, service };
}

describe('Account export v2 and deletion safety', () => {
  it('returns bounded owner data inside a repeatable-read transaction', async () => {
    const h = await accountHarness();
    const result = await h.service.exportAccount(REQ, { currentPassword: PASSWORD });

    expect(result.formatVersion).toBe(2);
    expect(result.account.id).toBe(UID);
    expect(result.security.sessions).toHaveLength(200);
    expect(result.security.recentEvents).toHaveLength(1000);
    expect(result.completeness).toEqual({
      sessionsTruncated: true,
      eventsTruncated: true,
      medicalRecordsIncluded: false,
      avatarFileIncluded: false
    });

    expect(result.limits).toEqual({
      maximumSessions: 200,
      maximumSecurityEvents: 1000,
      securityEventWindowDays: 90
    });

    expect(h.prisma.$transaction).toHaveBeenCalledWith(expect.any(Function), { isolationLevel: 'RepeatableRead' });
    expect(h.mfa.verifySensitiveActionInTransaction).toHaveBeenCalledWith(h.tx, UID, SID, 4, undefined);

    expect(h.tx.authSession.findMany).toHaveBeenCalledWith(
      expect.objectContaining({where:{userId:UID},take:201})
    );

    const query = h.tx.securityEvent.findMany.mock.calls[0][0];

    expect(query.where.userId).toBe(UID);
    expect(Math.abs(Date.now() - query.where.createdAt.gte.getTime() - 90*86400000)).toBeLessThan(5000);

    const fields = h.tx.user.findFirst.mock.calls[0][0].select;
    expect(fields).not.toHaveProperty('passwordHash');
    expect(fields).not.toHaveProperty('avatarUrl');
    expect(fields.socialAccounts.select).toEqual({provider:true,createdAt:true});
  });

  it('rejects export with a wrong password before transaction', async () => {
    const h = await accountHarness();
    await expect(h.service.exportAccount(REQ, {currentPassword:'wrong'})).rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('rejects export when MFA fails without reading protected data', async () => {
    const h = await accountHarness();
    h.mfa.verifySensitiveActionInTransaction.mockResolvedValue(false);
    await expect(h.service.exportAccount(REQ, {currentPassword:PASSWORD, mfaCode:'123456'})).rejects.toBeInstanceOf(BadRequestException);
    expect(h.tx.user.findFirst).not.toHaveBeenCalled();
    expect(h.tx.authSession.findMany).not.toHaveBeenCalled();
  });

  it('rejects export from a revoked session', async () => {
    const h = await accountHarness();
    h.tx.authSession.findFirst.mockResolvedValue(null);
    await expect(h.service.exportAccount(REQ, {currentPassword:PASSWORD})).rejects.toBeInstanceOf(UnauthorizedException);
    expect(h.tx.authSession.findMany).not.toHaveBeenCalled();
  });

  it('requires explicit deletion confirmation', async () => {
    const h = await accountHarness();
    await expect(h.service.deleteAccount(REQ, {currentPassword:PASSWORD,confirmation:'NO'})).rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.user.findUnique).not.toHaveBeenCalled();
  });

  it('does not allow privileged account deletion through the patient endpoint', async () => {
    const h = await accountHarness();
    h.prisma.user.findUnique.mockResolvedValue({...h.user,role:'ADMIN'});
    await expect(h.service.deleteAccount(REQ, {currentPassword:PASSWORD,confirmation:'DELETE'})).rejects.toBeInstanceOf(BadRequestException);
    expect(h.tx.user.delete).not.toHaveBeenCalled();
  });

  it('queues an owned avatar before deleting the account', async () => {
    const h = await accountHarness();
    const key = `avatars/${UID}/${RID}.jpg`;

    h.tx.user.findFirst.mockResolvedValue({id:UID,avatarUrl:key});

    await expect(h.service.deleteAccount(REQ, {currentPassword:PASSWORD,confirmation:'DELETE'})).resolves.toMatchObject({
      accountDeleted:true,
      avatarCleanupQueued:true
    });

    expect(h.tx.avatarCleanupJob.upsert).toHaveBeenCalledWith({
      where:{objectKey:key},
      create:{objectKey:key,notBefore:expect.any(Date)},
      update:{}
    });

    expect(h.tx.user.delete).toHaveBeenCalledWith({where:{id:UID}});

    expect(h.tx.avatarCleanupJob.upsert.mock.invocationCallOrder[0])
      .toBeLessThan(h.tx.user.delete.mock.invocationCallOrder[0]);
  });

  it('rejects a foreign avatar reference rather than deleting it', async () => {
    const h = await accountHarness();
    h.tx.user.findFirst.mockResolvedValue({id:UID,avatarUrl:`avatars/${SID}/${RID}.jpg`});

    await expect(h.service.deleteAccount(REQ, {currentPassword:PASSWORD,confirmation:'DELETE'})).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.delete).not.toHaveBeenCalled();
    expect(h.tx.avatarCleanupJob.upsert).not.toHaveBeenCalled();
  });

  it('requests Google export proof bound to the authenticated session', async () => {
    const h = await accountHarness();
    await h.service.requestGoogleDataChallenge(REQ, {action:'EXPORT_DATA',idToken:'mock-google-credential'});
    expect(h.google.request).toHaveBeenCalledWith(UID,SID,'EXPORT_DATA','mock-google-credential');
  });
});

describe('Security activity pagination and audit event throttling', () => {
  it.each(['','not-a-cursor','2026-01-01~'+RID,'2026-01-01T00:00:00.000Z~bad'])('rejects invalid cursor %s', cursor => {
    expect(() => parseActivityCursor(cursor)).toThrow(BadRequestException);
  });

  it('parses a canonical cursor', () => {
    expect(parseActivityCursor('2026-01-01T00:00:00.000Z~'+RID)).toEqual({
      createdAt:new Date('2026-01-01T00:00:00.000Z'),
      id:RID
    });
  });

  it('limits history to 50 owner-scoped events', async () => {
    const when = new Date();
    const events = Array.from({length:51}, (_,i) => ({
      id: `33333333-3333-4333-8333-${String(100+i).padStart(12,'0')}`,
      type:'SESSION_CREATED',
      createdAt:when
    }));

    const findMany = vi.fn().mockResolvedValue(events);

    const service = new AuthSessionService(
      {securityEvent:{findMany}} as never,
      {} as never,
      {} as never
    );

    const page = await service.listSecurityActivity(UID);

    expect(page.events).toHaveLength(50);
    expect(page.hasMore).toBe(true);
    expect(page.nextCursor).toBe(when.toISOString()+'~'+events[49].id);

    await service.listSecurityActivity(UID,page.nextCursor!);

    expect(findMany).toHaveBeenLastCalledWith(expect.objectContaining({
      where:expect.objectContaining({
        userId:UID,
        createdAt:{gte:expect.any(Date)},
        OR:[
          {createdAt:{lt:when}},
          {createdAt:when,id:{lt:events[49].id}}
        ]
      }),
      take:51
    }));
  });

  it('suppresses a repeated event but records a new one', async () => {
    const tx = {
      securityEvent:{
        findFirst:vi.fn().mockResolvedValueOnce({id:RID}).mockResolvedValueOnce(null),
        create:vi.fn().mockResolvedValue({})
      }
    };

    const now = new Date();

    await recordLimitedSecurityEvent(tx as never,UID,'MFA_VERIFICATION_FAILED',now);
    expect(tx.securityEvent.create).not.toHaveBeenCalled();

    await recordLimitedSecurityEvent(tx as never,UID,'MFA_VERIFICATION_FAILED',now);

    expect(tx.securityEvent.create).toHaveBeenCalledWith({
      data:{userId:UID,type:'MFA_VERIFICATION_FAILED',createdAt:now}
    });
  });
});

describe('Database rate limiting and lifecycle', () => {
  it.each([[0,5,1],[1000,0,1],[1000,5,604800001]])('rejects invalid limits before SQL', async (ttl,limit,block) => {
    const query = vi.fn();
    const storage = new PostgresRateLimitStorage({$queryRaw:query} as never);

    await expect(storage.increment('test',ttl,limit,block,'default')).rejects.toBeInstanceOf(ServiceUnavailableException);

    expect(query).not.toHaveBeenCalled();
  });

  it('hashes the key and reports a blocked bucket', async () => {
    const query = vi.fn().mockResolvedValue([{hits:6,blocked:true,remaining:5.2}]);
    const storage = new PostgresRateLimitStorage({$queryRaw:query} as never);

    await expect(storage.increment('test',1000,5,3000,'default')).resolves.toEqual({
      totalHits:6,
      timeToExpire:6,
      isBlocked:true,
      timeToBlockExpire:6
    });

    expect(query.mock.calls[0][1]).toBe(
      createHash('sha256').update(JSON.stringify(['default','test'])).digest('hex')
    );
  });

  it('fails closed on unavailable or empty database results', async () => {
    const query = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce([]);
    const storage = new PostgresRateLimitStorage({$queryRaw:query} as never);

    for(let i=0;i<2;i++) {
      await expect(storage.increment('test',1000,5,3000,'default')).rejects.toBeInstanceOf(ServiceUnavailableException);
    }
  });

  it('performs bounded lifecycle cleanup and waits for shutdown', async () => {
    vi.useFakeTimers();

    const run = vi.fn().mockResolvedValue(0);
    const service = new SecurityLifecycleService({$executeRaw:run} as never);

    service.onModuleInit();
    await vi.advanceTimersByTimeAsync(600000);
    await service.onModuleDestroy();

    expect(run).toHaveBeenCalledTimes(3);

    expect(run.mock.calls.map(c => Array.from(c[0] as string[]).join('?'))).toEqual([
      expect.stringContaining('LIMIT 500'),
      expect.stringContaining('LIMIT 1000'),
      expect.stringContaining('LIMIT 2000')
    ]);

    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('Security notification outbox', () => {
  it('preserves explicit verified recipient and locale', async () => {
    const tx = {
      user:{
        findUnique:vi.fn().mockResolvedValue({
          email:EMAIL,
          emailVerifiedAt:new Date(),
          preferredLanguage:'ja'
        })
      },
      securityNotification:{
        create:vi.fn().mockResolvedValue({})
      }
    };

    await enqueueSecurityNotification(tx as never,UID,'EMAIL_CHANGED','old@example.test');

    expect(tx.securityNotification.create).toHaveBeenCalledWith({
      data:{
        userId:UID,
        recipient:'old@example.test',
        kind:'EMAIL_CHANGED',
        language:'ja'
      }
    });
  });

  it.each([[200,true,false],[429,false,false],[403,false,true]] as const)('handles provider status %s with lease ownership', async (status,delivered,failed) => {
    const jobs = {
      updateMany:vi.fn().mockResolvedValue({count:1}),
      deleteMany:vi.fn().mockResolvedValue({count:0}),
      findMany:vi.fn().mockResolvedValue([{
        id:RID,
        recipient:EMAIL,
        kind:'PASSWORD_CHANGED',
        language:'en',
        attempts:0,
        createdAt:new Date()
      }])
    };

    const worker = new SecurityNotificationService(
      {securityNotification:jobs} as never,
      {get:()=> 'test-only'} as never
    );

    const send = vi.fn().mockResolvedValue(new Response(null,{status}));
    vi.stubGlobal('fetch',send);

    await (worker as unknown as {processBatch():Promise<void>}).processBatch();

    expect(send).toHaveBeenCalledWith(
      'https://api.resend.com/emails',
      expect.objectContaining({
        headers:expect.objectContaining({
          'Idempotency-Key':'ted-security-'+RID
        })
      })
    );

    const claim = jobs.updateMany.mock.calls[1][0].data.claimId;
    const final = jobs.updateMany.mock.calls[2][0];

    expect(final.where).toMatchObject({
      id:RID,
      claimId:claim,
      deliveredAt:null,
      failedAt:null
    });

    if(delivered) {
      expect(final.data).toMatchObject({deliveredAt:expect.any(Date),recipient:''});
    } else if(failed) {
      expect(final.data).toMatchObject({failedAt:expect.any(Date),recipient:''});
    } else {
      expect(final.data).toMatchObject({claimId:null,notBefore:expect.any(Date)});
      expect(final.data).not.toHaveProperty('recipient');
    }
  });
});

describe('Account route contracts', () => {
  it('binds email change confirmation to the authenticated session', async () => {
    const service = {
      request:vi.fn().mockResolvedValue({requestId:RID}),
      confirm:vi.fn().mockResolvedValue({message:'done'})
    };

    const controller = new EmailChangeController(service as never);

    await controller.request(REQ,{newEmail:'next@example.test',currentPassword:PASSWORD,mfaCode:'123456'});
    await controller.confirm(REQ,{requestId:RID,oldCode:'12345678',newCode:'87654321'});

    expect(service.request).toHaveBeenCalledWith(UID,SID,'next@example.test',PASSWORD,'123456');
    expect(service.confirm).toHaveBeenCalledWith(UID,SID,RID,'12345678','87654321');
  });

  it('lists a Google-only account without exposing the password hash', async () => {
    const prisma={
      user:{
        findUnique:vi.fn().mockResolvedValue({
          isActive:true,
          emailVerifiedAt:new Date(),
          passwordHash:null,
          socialAccounts:[{provider:'GOOGLE',createdAt:new Date()}]
        })
      }
    };

    const service=new ConnectedAccountsService(
      prisma as never,
      {} as never,
      {} as never,
      {} as never
    );

    await expect(service.list(UID)).resolves.toMatchObject({
      hasPassword:false,
      canManageConnections:false,
      canSetPassword:true
    });

    const result=await service.list(UID);
    expect(result).not.toHaveProperty('passwordHash');
  });
});

describe('Google action challenge binding and consumption', () => {
  function fixture() {
    const code='12345678';
    const secret='test-challenge-secret';

    const binding={
      userId:UID,
      requestId:RID,
      sessionId:SID,
      sessionVersion:4,
      action:'EXPORT_DATA' as const,
      googleSubject:'test-subject',
      email:EMAIL
    };

    const codeHash=createHmac('sha256',secret)
      .update(JSON.stringify(['ted:google-action:v1',UID,RID,SID,4,'EXPORT_DATA','test-subject',EMAIL,code]))
      .digest('hex');

    const record={
      ...binding,
      codeHash,
      consumedAt:null,
      attempts:0,
      expiresAt:new Date(Date.now()+600000)
    };

    const tx={
      $queryRaw:vi.fn().mockResolvedValue([]),
      user:{
        findUnique:vi.fn().mockResolvedValue({
          id:UID,isActive:true,role:'PATIENT',
          passwordHash:null,email:EMAIL,sessionVersion:4
        })
      },
      authSession:{
        findFirst:vi.fn().mockResolvedValue({id:SID})
      },
      socialAccount:{
        findUnique:vi.fn().mockResolvedValue({providerUserId:'test-subject'})
      },
      googleActionChallenge:{
        findUnique:vi.fn().mockResolvedValue(record),
        updateMany:vi.fn().mockResolvedValue({count:1})
      }
    };

    const prisma={
      $transaction:vi.fn(async (fn:(client:typeof tx)=>Promise<unknown>)=>fn(tx))
    };

    const mfa={
      verifySensitiveActionInTransaction:vi.fn().mockResolvedValue(true)
    };

    const service=new GoogleActionChallengeService(
      prisma as never,
      {getOrThrow:()=>secret} as never,
      mfa as never
    );

    return {
      tx,prisma,mfa,service,record,
      input:{
        userId:UID,
        sessionId:SID,
        requestId:RID,
        action:'EXPORT_DATA' as const,
        code
      },
      operation:vi.fn().mockResolvedValue('done')
    };
  }

  it('consumes proof before executing the owner-scoped operation',async()=>{
    const h=fixture();

    await expect(h.service.execute(h.input,h.operation)).resolves.toBe('done');

    expect(h.prisma.$transaction).toHaveBeenCalledWith(
      expect.any(Function),
      {isolationLevel:'RepeatableRead'}
    );

    expect(h.mfa.verifySensitiveActionInTransaction).toHaveBeenCalledWith(
      h.tx,UID,SID,4,undefined
    );

    expect(h.tx.googleActionChallenge.updateMany).toHaveBeenCalledWith(expect.objectContaining({
      where:expect.objectContaining({userId:UID,requestId:RID,consumedAt:null}),
      data:{consumedAt:expect.any(Date)}
    }));

    expect(h.operation).toHaveBeenCalledWith(
      h.tx,{userId:UID,email:EMAIL,googleSubject:'test-subject',sessionVersion:4}
    );

    expect(h.tx.googleActionChallenge.updateMany.mock.invocationCallOrder[0])
      .toBeLessThan(h.operation.mock.invocationCallOrder[0]);
  });

  it.each(['sessionId','action','googleSubject','sessionVersion','consumedAt'] as const)('rejects mismatched or consumed proof field %s',async key=>{
    const h=fixture();

    const changes={
      sessionId:RID,
      action:'DELETE_ACCOUNT',
      googleSubject:'different-subject',
      sessionVersion:5,
      consumedAt:new Date()
    };

    h.tx.googleActionChallenge.findUnique.mockResolvedValue({
      ...h.record,[key]:changes[key]
    });

    await expect(h.service.execute(h.input,h.operation)).rejects.toBeInstanceOf(BadRequestException);

    expect(h.mfa.verifySensitiveActionInTransaction).not.toHaveBeenCalled();
    expect(h.operation).not.toHaveBeenCalled();
  });

  it('increments an invalid email-code attempt without executing the operation',async()=>{
    const h=fixture();

    await expect(h.service.execute({...h.input,code:'87654321'},h.operation)).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.googleActionChallenge.updateMany).toHaveBeenCalledWith(expect.objectContaining({
      data:{attempts:{increment:1}}
    }));

    expect(h.operation).not.toHaveBeenCalled();
  });

  it('does not consume proof if MFA is rejected',async()=>{
    const h=fixture();
    h.mfa.verifySensitiveActionInTransaction.mockResolvedValue(false);

    await expect(h.service.execute(h.input,h.operation)).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.googleActionChallenge.updateMany).not.toHaveBeenCalled();
    expect(h.operation).not.toHaveBeenCalled();
  });

  it('does not execute after concurrent consumption loses compare-and-set',async()=>{
    const h=fixture();
    h.tx.googleActionChallenge.updateMany.mockResolvedValue({count:0});

    await expect(h.service.execute(h.input,h.operation)).rejects.toBeInstanceOf(BadRequestException);

    expect(h.operation).not.toHaveBeenCalled();
  });


  it('rejects malformed Google action proof before database access', async () => {
    const h = fixture();

    await expect(h.service.execute({
      ...h.input,
      code: 'invalid'
    }, h.operation)).rejects.toBeInstanceOf(BadRequestException);

    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('rejects a malformed stored Google proof digest', async () => {
    const h = fixture();

    h.tx.googleActionChallenge.findUnique.mockResolvedValue({
      ...h.record,
      codeHash: 'invalid-hash'
    });

    await expect(h.service.execute(
      h.input, h.operation
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.operation).not.toHaveBeenCalled();
  });

  it.each([true, false])(
    'checks patient eligibility during Google deletion: %s',
    async eligible => {
      const h = fixture();

      const findFirst = vi.fn().mockResolvedValue(
        eligible ? { id: UID } : null
      );

      Object.assign(h.tx.user, { findFirst });

      const action = 'DELETE_ACCOUNT' as const;

      const codeHash = createHmac('sha256', 'test-challenge-secret')
        .update(JSON.stringify([
          'ted:google-action:v1',
          UID, RID, SID, 4, action,
          'test-subject', EMAIL, h.input.code
        ])).digest('hex');

      h.tx.googleActionChallenge.findUnique.mockResolvedValue({
        ...h.record, action, codeHash
      });

      const execution = h.service.execute({
        ...h.input, action
      }, h.operation);

      if (eligible) {
        await expect(execution).resolves.toBe('done');

        expect(h.prisma.$transaction).toHaveBeenCalledWith(
          expect.any(Function),
          { isolationLevel: 'ReadCommitted' }
        );
      } else {
        await expect(execution).rejects.toBeInstanceOf(BadRequestException);
        expect(h.operation).not.toHaveBeenCalled();
      }

      expect(findFirst).toHaveBeenCalledWith({
        where: { id: UID, isActive: true, role: 'PATIENT' },
        select: { id: true }
      });
    }
  );

});

describe('Dual mailbox verification',()=>{
  const NEXT='next@example.test';
  const OLD_CODE='12345678';
  const NEW_CODE='87654321';
  const KEY='test-email-change-secret';

  function fixture(){
    const digest=(side:string,code:string)=>createHmac('sha256',KEY)
      .update('ted:email-change:v1:'+UID+':'+RID+':'+side+':'+code)
      .digest('hex');

    const user={
      id:UID,email:EMAIL,isActive:true,
      emailVerifiedAt:new Date(),
      passwordHash:'test-hash',
      sessionVersion:4,
      _count:{socialAccounts:0},
      preferredLanguage:'en'
    };

    const record={
      requestId:RID,
      sessionId:SID,
      sessionVersion:4,
      oldEmail:EMAIL,
      newEmail:NEXT,
      oldCodeHash:digest('old',OLD_CODE),
      newCodeHash:digest('new',NEW_CODE),
      attempts:0,
      expiresAt:new Date(Date.now()+600000)
    };

    const tx={
      $queryRaw:vi.fn().mockResolvedValue([]),
      user:{
        findUnique:vi.fn().mockResolvedValue(user),
        updateMany:vi.fn().mockResolvedValue({count:1})
      },
      authSession:{
        findFirst:vi.fn().mockResolvedValue({id:SID}),
        updateMany:vi.fn().mockResolvedValue({count:1})
      },
      emailChangeRequest:{
        findUnique:vi.fn().mockResolvedValue(record),
        update:vi.fn().mockResolvedValue({}),
        updateMany:vi.fn().mockResolvedValue({count:1})
      },
      passwordResetCode:{
        deleteMany:vi.fn().mockResolvedValue({count:1})
      },
      emailVerificationCode:{
        updateMany:vi.fn().mockResolvedValue({count:1})
      },
      googleActionChallenge:{
        updateMany:vi.fn().mockResolvedValue({count:1})
      },
      securityEvent:{
        create:vi.fn().mockResolvedValue({})
      },
      securityNotification:{
        create:vi.fn().mockResolvedValue({})
      }
    };

    const prisma={
      $transaction:vi.fn(async(fn:(client:typeof tx)=>Promise<unknown>)=>fn(tx))
    };

    return {
      tx,record,user,
      service:new EmailChangeService(
        prisma as never,
        {getOrThrow:()=>KEY} as never,
        {} as never
      )
    };
  }

  it.each([[OLD_CODE,'00000000'],['00000000',NEW_CODE]])('requires both valid mailbox codes',async(oldCode,newCode)=>{
    const h=fixture();

    await expect(h.service.confirm(UID,SID,RID,oldCode,newCode)).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.emailChangeRequest.update).toHaveBeenCalledWith({
      where:{userId:UID},
      data:{attempts:{increment:1}}
    });

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
  });

  it('rejects proof reserved for another session',async()=>{
    const h=fixture();
    h.tx.emailChangeRequest.findUnique.mockResolvedValue({...h.record,sessionId:RID});

    await expect(h.service.confirm(UID,SID,RID,OLD_CODE,NEW_CODE)).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
  });

  it('updates email, revokes sessions, consumes proof and queues both notifications',async()=>{
    const h=fixture();
    const send=vi.fn();
    vi.stubGlobal('fetch',send);

    await expect(h.service.confirm(UID,SID,RID,OLD_CODE,NEW_CODE)).resolves.toEqual({
      message:'Email changed. Sign in again.'
    });

    expect(h.tx.user.updateMany).toHaveBeenCalledWith(expect.objectContaining({
      where:expect.objectContaining({id:UID,email:EMAIL,sessionVersion:4}),
      data:{email:NEXT,emailVerifiedAt:expect.any(Date),sessionVersion:{increment:1}}
    }));

    expect(h.tx.authSession.updateMany).toHaveBeenCalledWith({
      where:{userId:UID,revokedAt:null},
      data:{revokedAt:expect.any(Date)}
    });

    expect(h.tx.emailChangeRequest.updateMany).toHaveBeenCalledWith(expect.objectContaining({
      where:expect.objectContaining({userId:UID,requestId:RID,sessionId:SID}),
      data:{attempts:5}
    }));

    for(const recipient of [EMAIL,NEXT]){
      expect(h.tx.securityNotification.create).toHaveBeenCalledWith({
        data:{userId:UID,recipient,kind:'EMAIL_CHANGED',language:'en'}
      });
    }

    expect(send).not.toHaveBeenCalled();
  });


  it('rejects a malformed stored mailbox digest', async () => {
    const h = fixture();

    h.tx.emailChangeRequest.findUnique.mockResolvedValue({
      ...h.record,
      oldCodeHash: 'corrupt'
    });

    await expect(h.service.confirm(
      UID, SID, RID, OLD_CODE, NEW_CODE
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.updateMany).not.toHaveBeenCalled();
  });

  it('rejects a concurrent email update that loses compare-and-set', async () => {
    const h = fixture();
    h.tx.user.updateMany.mockResolvedValue({ count: 0 });

    await expect(h.service.confirm(
      UID, SID, RID, OLD_CODE, NEW_CODE
    )).rejects.toThrow('Account changed');

    expect(h.tx.securityNotification.create).not.toHaveBeenCalled();
  });

  it('rejects a concurrently consumed mailbox proof', async () => {
    const h = fixture();

    h.tx.emailChangeRequest.updateMany.mockResolvedValue({ count: 0 });

    await expect(h.service.confirm(
      UID, SID, RID, OLD_CODE, NEW_CODE
    )).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.securityNotification.create).not.toHaveBeenCalled();
  });

  it('maps a real database uniqueness error to an email conflict', async () => {
    const h = fixture();

    h.tx.user.updateMany.mockRejectedValue(
      new CloseoutPrisma.PrismaClientKnownRequestError(
        'test uniqueness conflict',
        { code: 'P2002', clientVersion: '6.19.3' }
      )
    );

    await expect(h.service.confirm(
      UID, SID, RID, OLD_CODE, NEW_CODE
    )).rejects.toThrow('Email address is unavailable');
  });

});


describe('Additional account export and deletion boundaries', () => {
  const proof = {
    requestId: RID,
    emailCode: '12345678'
  };

  it('executes Google export using the authenticated proof binding', async () => {
    const h = await accountHarness();

    h.google.execute.mockImplementation(async (
      _input,
      operation
    ) => operation(h.tx, {
      userId: UID,
      email: EMAIL,
      sessionVersion: 4
    }));

    const data = await h.service.exportGoogleAccount(REQ, proof);

    expect(data).toMatchObject({
      formatVersion: 2,
      account: { id: UID }
    });

    expect(h.google.execute).toHaveBeenCalledWith({
      userId: UID,
      sessionId: SID,
      requestId: RID,
      action: 'EXPORT_DATA',
      code: '12345678',
      mfaCode: undefined
    }, expect.any(Function));

    expect(h.tx.user.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: UID,
          passwordHash: null,
          sessionVersion: 4
        })
      })
    );
  });

  it('requires explicit Google deletion confirmation', async () => {
    const h = await accountHarness();

    await expect(h.service.deleteGoogleAccount(REQ, {
      ...proof,
      confirmation: 'NO'
    })).rejects.toBeInstanceOf(BadRequestException);

    expect(h.google.execute).not.toHaveBeenCalled();
  });

  it('deletes a verified Google-only patient with no avatar', async () => {
    const h = await accountHarness();

    h.tx.user.findFirst.mockResolvedValue({
      id: UID, avatarUrl: null
    });

    h.google.execute.mockImplementation(async (
      _input,
      operation
    ) => operation(h.tx, {
      userId: UID,
      email: EMAIL,
      sessionVersion: 4
    }));

    await expect(h.service.deleteGoogleAccount(REQ, {
      ...proof, confirmation: 'DELETE'
    })).resolves.toMatchObject({
      accountDeleted: true,
      avatarCleanupQueued: false
    });

    expect(h.tx.user.delete).toHaveBeenCalledWith({
      where: { id: UID }
    });

    expect(h.tx.avatarCleanupJob.upsert).not.toHaveBeenCalled();
  });

  it('rejects a privileged account before Google deletion proof', async () => {
    const h = await accountHarness();

    h.prisma.user.findUnique.mockResolvedValue({
      ...h.user, role: 'ADMIN'
    });

    await expect(
      h.service.requestGoogleDataChallenge(REQ, {
        action: 'DELETE_ACCOUNT',
        idToken: 'test-credential'
      })
    ).rejects.toBeInstanceOf(BadRequestException);

    expect(h.google.request).not.toHaveBeenCalled();
  });

  it('rejects missing Google deletion account', async () => {
    const h = await accountHarness();

    h.prisma.user.findUnique.mockResolvedValue(null);

    await expect(
      h.service.requestGoogleDataChallenge(REQ, {
        action: 'DELETE_ACCOUNT',
        idToken: 'test-credential'
      })
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('requests proof for an eligible patient deletion', async () => {
    const h = await accountHarness();

    await h.service.requestGoogleDataChallenge(REQ, {
      action: 'DELETE_ACCOUNT',
      idToken: 'test-credential'
    });

    expect(h.google.request).toHaveBeenCalledWith(
      UID, SID, 'DELETE_ACCOUNT', 'test-credential'
    );
  });

  it.each([null, false])(
    'rejects inactive or missing account export',
    async active => {
      const h = await accountHarness();

      h.prisma.user.findUnique.mockResolvedValue(
        active === null ? null : {
          ...h.user, isActive: false
        }
      );

      await expect(h.service.exportAccount(REQ, {
        currentPassword: PASSWORD
      })).rejects.toBeInstanceOf(UnauthorizedException);
    }
  );

  it('requires a verified password for password export', async () => {
    const h = await accountHarness();

    h.prisma.user.findUnique.mockResolvedValue({
      ...h.user, emailVerifiedAt: null
    });

    await expect(h.service.exportAccount(REQ, {
      currentPassword: PASSWORD
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects a changed account during export', async () => {
    const h = await accountHarness();

    h.tx.user.findFirst.mockResolvedValue(null);

    await expect(h.service.exportAccount(REQ, {
      currentPassword: PASSWORD
    })).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.authSession.findMany).not.toHaveBeenCalled();
  });

  it('rejects account deletion after failed MFA', async () => {
    const h = await accountHarness();

    h.mfa.verifySensitiveActionInTransaction.mockResolvedValue(false);

    await expect(h.service.deleteAccount(REQ, {
      currentPassword: PASSWORD,
      confirmation: 'DELETE'
    })).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.delete).not.toHaveBeenCalled();
  });

  it('rejects deletion after the account disappears', async () => {
    const h = await accountHarness();

    h.tx.user.findFirst.mockResolvedValue(null);

    await expect(h.service.deleteAccount(REQ, {
      currentPassword: PASSWORD,
      confirmation: 'DELETE'
    })).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('rejects deletion after requesting session expires', async () => {
    const h = await accountHarness();

    h.tx.authSession.findFirst.mockResolvedValue(null);

    await expect(h.service.deleteAccount(REQ, {
      currentPassword: PASSWORD,
      confirmation: 'DELETE'
    })).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.tx.user.delete).not.toHaveBeenCalled();
  });
});


describe('Final deletion authorization cases', () => {
  it('rejects deletion when the owner no longer exists', async () => {
    const h = await accountHarness();
    h.prisma.user.findUnique.mockResolvedValue(null);

    await expect(h.service.deleteAccount(REQ, {
      currentPassword: PASSWORD,
      confirmation: 'DELETE'
    })).rejects.toBeInstanceOf(UnauthorizedException);

    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('requires verified password ownership for account deletion', async () => {
    const h = await accountHarness();

    h.prisma.user.findUnique.mockResolvedValue({
      ...h.user,
      emailVerifiedAt: null
    });

    await expect(h.service.deleteAccount(REQ, {
      currentPassword: PASSWORD,
      confirmation: 'DELETE'
    })).rejects.toBeInstanceOf(BadRequestException);

    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });

  it('rejects incorrect deletion credentials', async () => {
    const h = await accountHarness();

    await expect(h.service.deleteAccount(REQ, {
      currentPassword: 'wrong',
      confirmation: 'DELETE'
    })).rejects.toBeInstanceOf(BadRequestException);

    expect(h.tx.user.delete).not.toHaveBeenCalled();
  });
});
