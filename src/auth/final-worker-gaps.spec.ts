
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Prisma } from '@prisma/client';
import { Logger } from '@nestjs/common';

import { AvatarService } from './avatar/avatar.service';
import { SecurityLifecycleService } from './security/security-lifecycle.service';
import { SecurityActivityService } from './security/security-activity.service';
import { SecurityNotificationService } from '../notifications/security-notification.service';
import {
  normalizeNotificationLanguage,
  localizedSecurityText
} from '../notifications/security-notification.locales';
import { HttpExceptionFilter } from '../common/filters/http-exception.filter';
import { PostgresRateLimitStorage } from '../common/config/postgres-rate-limit.storage';

const UID = '11111111-1111-4111-8111-111111111111';
const RID = '33333333-3333-4333-8333-333333333333';
const KEY = 'avatars/' + UID + '/' + RID + '.jpg';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('Avatar durable cleanup', () => {
  function fixture() {
    const job = {
      objectKey: KEY,
      attempts: 0,
      notBefore: new Date(Date.now() - 60000)
    };

    const jobs = {
      findMany: vi.fn().mockResolvedValue([job]),
      updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      deleteMany: vi.fn().mockResolvedValue({ count: 1 })
    };

    const users = {
      findFirst: vi.fn().mockResolvedValue(null)
    };

    const service = new AvatarService(
      {
        avatarCleanupJob: jobs,
        user: users
      } as never,
      {} as never
    );

    const client = {
      send: vi.fn().mockResolvedValue({}),
      destroy: vi.fn()
    };

    const storage = vi.spyOn(
      service as unknown as {
        storage(): unknown
      },
      'storage'
    ).mockReturnValue({
      client,
      bucket: 'test-bucket'
    });

    const drain = () => (
      service as unknown as {
        drainCleanup(): Promise<void>
      }
    ).drainCleanup();

    return {
      job, jobs, users,
      client, storage, service, drain
    };
  }

  it('claims a cleanup lease and deletes only an unreferenced object', async () => {
    const h = fixture();

    await h.drain();

    expect(h.jobs.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ take: 20 })
    );

    expect(h.jobs.updateMany).toHaveBeenCalledWith({
      where: {
        objectKey: KEY,
        attempts: 0,
        notBefore: h.job.notBefore
      },
      data: {
        attempts: { increment: 1 },
        notBefore: expect.any(Date)
      }
    });

    expect(h.users.findFirst).toHaveBeenCalledWith({
      where: { avatarUrl: KEY },
      select: { id: true }
    });

    expect(h.client.send).toHaveBeenCalledOnce();
    expect(h.client.destroy).toHaveBeenCalledOnce();

    expect(h.jobs.deleteMany).toHaveBeenCalledWith({
      where: { objectKey: KEY, attempts: 1 }
    });
  });

  it('never deletes a currently referenced avatar', async () => {
    const h = fixture();

    h.users.findFirst.mockResolvedValue({ id: UID });

    await h.drain();

    expect(h.client.send).not.toHaveBeenCalled();
    expect(h.jobs.deleteMany).not.toHaveBeenCalled();
  });

  it('does not delete after another worker wins the lease', async () => {
    const h = fixture();

    h.jobs.updateMany.mockResolvedValue({ count: 0 });

    await h.drain();

    expect(h.users.findFirst).not.toHaveBeenCalled();
    expect(h.client.send).not.toHaveBeenCalled();
  });

  it('defers an invalid storage reference for review', async () => {
    const h = fixture();

    h.jobs.findMany.mockResolvedValue([{
      ...h.job, objectKey: 'unmanaged-object'
    }]);

    await h.drain();

    expect(h.jobs.updateMany).toHaveBeenCalledWith({
      where: {
        objectKey: 'unmanaged-object',
        attempts: 0
      },
      data: { notBefore: expect.any(Date) }
    });

    expect(h.client.send).not.toHaveBeenCalled();
  });

  it('retains durable cleanup after an object storage failure', async () => {
    const h = fixture();

    h.client.send.mockRejectedValue(new Error('storage unavailable'));

    await expect(h.drain()).resolves.toBeUndefined();

    expect(h.client.destroy).toHaveBeenCalledOnce();
    expect(h.jobs.deleteMany).not.toHaveBeenCalled();
  });

  it('recovers after temporary queue failure', async () => {
    const h = fixture();

    h.jobs.findMany.mockRejectedValueOnce(new Error('database unavailable'));

    await h.drain();
    await h.drain();

    expect(h.jobs.findMany).toHaveBeenCalledTimes(2);
    expect(h.jobs.deleteMany).toHaveBeenCalledOnce();
  });

  it('prevents concurrent drain operations', async () => {
    const h = fixture();

    let release!: (value: unknown[]) => void;

    h.jobs.findMany.mockReturnValue(
      new Promise(resolve => { release = resolve; })
    );

    const pending = h.drain();

    await h.drain();

    expect(h.jobs.findMany).toHaveBeenCalledOnce();

    release([]);
    await pending;
  });

  it('starts and stops the cleanup timer', async () => {
    vi.useFakeTimers();

    const h = fixture();

    h.jobs.findMany.mockResolvedValue([]);

    h.service.onModuleInit();

    await vi.advanceTimersByTimeAsync(60000);

    expect(h.jobs.findMany).toHaveBeenCalledOnce();

    h.service.onModuleDestroy();
    h.service.onModuleDestroy();

    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('Security cleanup lifecycle failure recovery', () => {
  it.each([
    SecurityActivityService,
    SecurityLifecycleService
  ])('recovers from database errors and stops cleanly', async Service => {
    vi.useFakeTimers();

    const execute = vi.fn()
      .mockRejectedValueOnce(new Error('database unavailable'))
      .mockResolvedValue(0);

    const service = new Service({
      $executeRaw: execute
    } as never);

    const warn = vi.spyOn(Logger.prototype, 'warn');

    service.onModuleInit();

    await vi.advanceTimersByTimeAsync(600000);

    expect(warn).toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(600000);

    expect(execute.mock.calls.length).toBeGreaterThan(1);

    await service.onModuleDestroy();
    await service.onModuleDestroy();

    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    SecurityActivityService,
    SecurityLifecycleService
  ])('does not overlap an unfinished cleanup', async Service => {
    vi.useFakeTimers();

    let release!: (value: number) => void;

    const execute = vi.fn()
      .mockImplementationOnce(() =>
        new Promise<number>(resolve => { release = resolve; })
      )
      .mockResolvedValue(0);

    const service = new Service({
      $executeRaw: execute
    } as never);

    service.onModuleInit();

    await vi.advanceTimersByTimeAsync(1200000);

    expect(execute).toHaveBeenCalledOnce();

    release(0);

    await service.onModuleDestroy();

    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('Notification worker lease and lifecycle', () => {
  function fixture() {
    const job = {
      id: RID,
      recipient: 'patient@example.test',
      kind: 'PASSWORD_CHANGED',
      language: 'en',
      attempts: 0,
      createdAt: new Date()
    };

    const jobs = {
      updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      deleteMany: vi.fn().mockResolvedValue({ count: 0 }),
      findMany: vi.fn().mockResolvedValue([job])
    };

    const config = {
      get: vi.fn().mockReturnValue('test-only')
    };

    const service = new SecurityNotificationService(
      { securityNotification: jobs } as never,
      config as never
    );

    const send = vi.fn().mockResolvedValue(
      new Response('test-response', { status: 200 })
    );

    vi.stubGlobal('fetch', send);

    const process = () => (
      service as unknown as {
        processBatch(): Promise<void>
      }
    ).processBatch();

    return { job, jobs, config, service, send, process };
  }

  it('does not deliver mail when configuration is missing', async () => {
    const h = fixture();

    h.config.get.mockReturnValue(undefined);

    await h.process();
    await h.process();

    expect(h.jobs.findMany).not.toHaveBeenCalled();
    expect(h.send).not.toHaveBeenCalled();
  });

  it('does not send after losing claim ownership', async () => {
    const h = fixture();

    h.jobs.updateMany
      .mockResolvedValueOnce({ count: 0 })
      .mockResolvedValueOnce({ count: 0 });

    await h.process();

    expect(h.send).not.toHaveBeenCalled();
  });

  it('terminates an invalid notification kind without contacting mail', async () => {
    const h = fixture();

    h.jobs.findMany.mockResolvedValue([{
      ...h.job, kind: 'INVALID'
    }]);

    await h.process();

    expect(h.send).not.toHaveBeenCalled();

    expect(h.jobs.updateMany).toHaveBeenLastCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          failedAt: expect.any(Date),
          recipient: ''
        })
      })
    );
  });

  it('clears recipient after successful delivery', async () => {
    const h = fixture();

    await h.process();

    expect(h.send).toHaveBeenCalledOnce();

    expect(h.jobs.updateMany).toHaveBeenLastCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          deliveredAt: expect.any(Date),
          recipient: ''
        })
      })
    );
  });

  it('starts polling and waits for shutdown', async () => {
    vi.useFakeTimers();

    const h = fixture();

    h.jobs.findMany.mockResolvedValue([]);

    h.service.onModuleInit();

    await vi.advanceTimersByTimeAsync(30000);

    expect(h.jobs.findMany).toHaveBeenCalledOnce();

    await h.service.onModuleDestroy();
    await h.service.onModuleDestroy();

    expect(vi.getTimerCount()).toBe(0);
  });

  it('recovers polling after a database failure', async () => {
    vi.useFakeTimers();

    const h = fixture();

    h.jobs.updateMany.mockRejectedValueOnce(
      new Error('database unavailable')
    );

    h.jobs.findMany.mockResolvedValue([]);

    h.service.onModuleInit();

    await vi.advanceTimersByTimeAsync(60000);
    await h.service.onModuleDestroy();

    expect(h.jobs.findMany).toHaveBeenCalledOnce();
  });

  it('falls back to English for unsupported locales', () => {
    expect(normalizeNotificationLanguage('unsupported')).toBe('en');
  });

  it('preserves the fallback text for an unknown translation key', () => {
    expect(localizedSecurityText(
      'unsupported', 'Unknown test text'
    )).toBe('Unknown test text');
  });


  it('awaits an unfinished worker batch and skips delivery during shutdown', async () => {
    vi.useFakeTimers();

    const h = fixture();
    let release!: (jobs: unknown[]) => void;

    h.jobs.findMany.mockImplementation(() =>
      new Promise(resolve => { release = resolve; })
    );

    h.service.onModuleInit();

    await vi.advanceTimersByTimeAsync(30000);

    expect(h.jobs.findMany).toHaveBeenCalledOnce();

    await vi.advanceTimersByTimeAsync(30000);

    expect(h.jobs.findMany).toHaveBeenCalledOnce();

    const shutdown = h.service.onModuleDestroy();

    release([h.job]);
    await shutdown;

    expect(h.send).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('preserves successful delivery when response-stream cleanup fails', async () => {
    const h = fixture();
    const cancel = vi.fn().mockRejectedValue(
      new Error('response stream unavailable')
    );

    h.send.mockResolvedValue({
      ok: true,
      status: 200,
      body: { cancel }
    });

    await h.process();

    expect(cancel).toHaveBeenCalledOnce();

    expect(h.jobs.updateMany).toHaveBeenLastCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          deliveredAt: expect.any(Date),
          recipient: ''
        })
      })
    );
  });

});

describe('Database exception response sanitization', () => {
  it.each([
    ['P2034', undefined, 409],
    ['P2010', '40001', 409],
    ['P2010', '40P01', 409],
    ['P2010', '55P03', 503],
    ['P2010', 'XXXXX', 500],
    ['P2024', undefined, 503],
    ['P2028', undefined, 503],
    ['P2037', undefined, 503],
    ['P1001', undefined, 503],
    ['P1002', undefined, 503],
    ['P2002', undefined, 500]
  ] as const)(
    'maps %s without exposing database details',
    (code, sqlState, expected) => {
      const exception = new Prisma.PrismaClientKnownRequestError(
        'private database detail',
        {
          code,
          clientVersion: '6.19.3',
          meta: sqlState ? { code: sqlState } : undefined
        }
      );

      const json = vi.fn();
      const status = vi.fn().mockReturnValue({ json });

      const host = {
        switchToHttp: () => ({
          getRequest: () => ({
            path: '/test',
            requestId: 'test-request'
          }),
          getResponse: () => ({ status })
        })
      };

      new HttpExceptionFilter().catch(exception, host as never);

      expect(status).toHaveBeenCalledWith(expected);

      const body = json.mock.calls[0][0];

      expect(body.error.status).toBe(expected);
      expect(body.error.requestId).toBe('test-request');

      expect(JSON.stringify(body))
        .not.toContain('private database detail');
    }
  );
});

describe('Rate limit fallback duration', () => {
  it('uses TTL when block duration is omitted and reports unblocked state', async () => {
    const query = vi.fn().mockResolvedValue([{
      hits: 1,
      blocked: false,
      remaining: 4.1
    }]);

    const storage = new PostgresRateLimitStorage({
      $queryRaw: query
    } as never);

    await expect(
      storage.increment('test', 5000, 5, 0, 'default')
    ).resolves.toEqual({
      totalHits: 1,
      timeToExpire: 5,
      isBlocked: false,
      timeToBlockExpire: 0
    });
  });
});
