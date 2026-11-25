import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  BadRequestException, ConflictException, NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';

// AWS and image processing are mocked: tests never contact a real R2 bucket.
// Each SDK command retains its input so the tests can validate the object key
// and required upload/cleanup behavior.
const mocks = vi.hoisted(() => ({
  send: vi.fn(),
  signedUrl: vi.fn(),
  sharp: vi.fn(),
  metadata: vi.fn(),
  toBuffer: vi.fn(),
  clients: [] as Array<Record<string, unknown>>,
}));

vi.mock('@aws-sdk/client-s3', () => {
  class S3Client {
    destroy() {}
    constructor(config: Record<string, unknown>) { mocks.clients.push(config); }
    send(command: unknown) { return mocks.send(command); }
  }
  class PutObjectCommand { constructor(public readonly input: Record<string, unknown>) {} }
  class GetObjectCommand { constructor(public readonly input: Record<string, unknown>) {} }
  class DeleteObjectCommand { constructor(public readonly input: Record<string, unknown>) {} }
  return { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand };
});

vi.mock('@aws-sdk/s3-request-presigner', () => ({
  getSignedUrl: mocks.signedUrl,
}));

vi.mock('sharp', () => ({ default: (...args: unknown[]) => mocks.sharp(...args) }));

import {
  PutObjectCommand, DeleteObjectCommand, GetObjectCommand,
} from '@aws-sdk/client-s3';
import { AvatarService } from './avatar/avatar.service';
import { AvatarController } from './avatar/avatar.controller';

const UID = '11111111-1111-4111-8111-111111111111';
const ACCOUNT = 'a'.repeat(32);
const BUCKET = 'ted-profile-avatars';
const GOOD_KEY = `avatars/${UID}/22222222-2222-4222-8222-222222222222.jpg`;
const FOREIGN_KEY = 'avatars/another-user/not-ours.jpg';
const URL = 'https://signed.example.test/avatar.jpg';
const PHOTO = { buffer: Buffer.from('fake-but-mocked-image'), size: 21, mimetype: 'image/png' };

beforeEach(() => {
  vi.resetAllMocks();
  mocks.clients.length = 0;
  mocks.send.mockResolvedValue({});
  mocks.signedUrl.mockResolvedValue(URL);
  mocks.metadata.mockResolvedValue({ format: 'png' });
  mocks.toBuffer.mockResolvedValue(Buffer.from('jpeg-bytes'));
  const pipe: {
    metadata: typeof mocks.metadata;
    rotate: ReturnType<typeof vi.fn>;
    resize: ReturnType<typeof vi.fn>;
    jpeg: ReturnType<typeof vi.fn>;
    toBuffer: typeof mocks.toBuffer;
  } = {
    metadata: mocks.metadata,
    rotate: vi.fn(),
    resize: vi.fn(),
    jpeg: vi.fn(),
    toBuffer: mocks.toBuffer,
  };
  pipe.rotate.mockReturnValue(pipe);
  pipe.resize.mockReturnValue(pipe);
  pipe.jpeg.mockReturnValue(pipe);
  mocks.sharp.mockReturnValue(pipe);
});

function harness() {
  const settings: Record<string, string | undefined> = {
    R2_ACCOUNT_ID: ACCOUNT,
    R2_BUCKET: BUCKET,
    R2_ACCESS_KEY_ID: 'test-access-key',
    R2_SECRET_ACCESS_KEY: 'test-secret-key',
  };
  const config = { get: vi.fn((key: string) => settings[key]) };
  const tx = {
    avatarCleanupJob: { create: vi.fn().mockResolvedValue({}), deleteMany: vi.fn().mockResolvedValue({ count: 1 }), upsert: vi.fn().mockResolvedValue({}) },
    user: {
      findUnique: vi.fn().mockResolvedValue({ avatarUrl: null as string | null }),
      updateMany: vi.fn().mockResolvedValue({ count: 1 }),
    },
  };
  const prisma = { ...tx, $transaction: vi.fn(async (fn: (client: typeof tx) => Promise<unknown>) => fn(tx)) };
  const service = new AvatarService(prisma as never, config as never);
  return { service, prisma, config, settings };
}

function commandsOf(type: typeof PutObjectCommand | typeof DeleteObjectCommand | typeof GetObjectCommand) {
  return mocks.send.mock.calls
    .map((args: unknown[]) => args[0])
    .filter((cmd: unknown) => cmd instanceof type) as Array<{ input: Record<string, unknown> }>;
}

describe('R2 avatar read and signed access', () => {
  it('returns null without reading R2 when the patient has no avatar', async () => {
    const h = harness();
    await expect(h.service.get(UID)).resolves.toEqual({ url: null });
    expect(mocks.signedUrl).not.toHaveBeenCalled();
    expect(mocks.clients).toHaveLength(0);
  });

  it('rejects an account that does not exist', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue(null);
    await expect(h.service.get(UID)).rejects.toBeInstanceOf(NotFoundException);
  });

  it('does not sign a foreign user object key', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ avatarUrl: FOREIGN_KEY });
    await expect(h.service.get(UID)).resolves.toEqual({ url: null });
    expect(mocks.signedUrl).not.toHaveBeenCalled();
  });

  it('generates a five-minute private URL for a key owned by the user', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ avatarUrl: GOOD_KEY });
    await expect(h.service.get(UID)).resolves.toEqual({ url: URL });
    expect(mocks.signedUrl).toHaveBeenCalledWith(
      expect.anything(), expect.any(GetObjectCommand), { expiresIn: 300 },
    );
    expect(mocks.signedUrl.mock.calls[0][1].input).toEqual({
      Bucket: BUCKET, Key: GOOD_KEY,
    });
    expect(mocks.clients[0]).toMatchObject({
      endpoint: `https://${ACCOUNT}.r2.cloudflarestorage.com`,
      region: 'auto',
      credentials: {
        accessKeyId: 'test-access-key', secretAccessKey: 'test-secret-key',
      },
    });
  });

  it('refuses to directly sign a reference outside the user namespace', async () => {
    const h = harness();
    const internal = h.service as unknown as { signed(id: string, key: string): Promise<string> };
    await expect(internal.signed(UID, FOREIGN_KEY))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(mocks.signedUrl).not.toHaveBeenCalled();
  });

  it.each([
    ['missing account', 'R2_ACCOUNT_ID', undefined],
    ['invalid account ID', 'R2_ACCOUNT_ID', 'not-a-valid-id'],
    ['missing bucket', 'R2_BUCKET', undefined],
    ['missing access key', 'R2_ACCESS_KEY_ID', undefined],
    ['missing secret', 'R2_SECRET_ACCESS_KEY', undefined],
  ])('fails closed with %s', async (_label, field, value) => {
    const h = harness();
    h.settings[field] = value;
    h.prisma.user.findUnique.mockResolvedValue({ avatarUrl: GOOD_KEY });
    await expect(h.service.get(UID))
      .rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(mocks.signedUrl).not.toHaveBeenCalled();
  });
});

describe('R2 avatar upload, replace, and failure cleanup', () => {
  it.each([
    ['missing file', undefined],
    ['empty buffer', { buffer: Buffer.alloc(0), size: 1, mimetype: 'image/png' }],
    ['zero-byte size', { buffer: Buffer.from('x'), size: 0, mimetype: 'image/png' }],
    ['over 3MB', { buffer: Buffer.from('x'), size: 3 * 1024 * 1024 + 1, mimetype: 'image/png' }],
  ] as const)('rejects %s before accessing the database or R2', async (_label, file) => {
    const h = harness();
    await expect(h.service.upload(UID, file)).rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.user.findUnique).not.toHaveBeenCalled();
    expect(mocks.send).not.toHaveBeenCalled();
  });

  it.each([
    ['metadata format is missing', undefined],
    ['unsupported GIF format', 'gif'],
  ])('rejects when %s', async (_name, format) => {
    const h = harness();
    mocks.metadata.mockResolvedValue({ format });
    await expect(h.service.upload(UID, PHOTO))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(h.prisma.user.findUnique).not.toHaveBeenCalled();
  });

  it('rejects malformed image payloads with a processing error', async () => {
    const h = harness();
    mocks.metadata.mockRejectedValue(new Error('decode failed'));
    await expect(h.service.upload(UID, PHOTO))
      .rejects.toBeInstanceOf(BadRequestException);
  });

  it('rejects a failed image resize/conversion', async () => {
    const h = harness();
    mocks.toBuffer.mockRejectedValue(new Error('image processing failed'));
    await expect(h.service.upload(UID, PHOTO))
      .rejects.toBeInstanceOf(BadRequestException);
  });

  it('converts, uploads, saves and signs a new JPEG avatar', async () => {
    const h = harness();
    const result = await h.service.upload(UID, PHOTO);
    expect(result).toEqual({ url: URL });
    expect(mocks.sharp).toHaveBeenCalledWith(PHOTO.buffer, {
      limitInputPixels: 20000000, failOn: 'error',
    });
    const put = commandsOf(PutObjectCommand);
    expect(put).toHaveLength(1);
    expect(put[0].input).toMatchObject({
      Bucket: BUCKET,
      Key: expect.stringMatching(/^avatars\/11111111-1111-4111-8111-111111111111\/[a-f0-9-]+\.jpg$/),
      Body: Buffer.from('jpeg-bytes'),
      ContentType: 'image/jpeg',
      CacheControl: 'private, no-store',
    });
    expect(h.prisma.user.updateMany).toHaveBeenCalledWith({
      where: { id: UID, avatarUrl: null },
      data: { avatarUrl: put[0].input.Key },
    });
    expect(commandsOf(DeleteObjectCommand)).toHaveLength(0);
    expect(h.prisma.avatarCleanupJob.create).toHaveBeenCalledWith({ data: { objectKey: put[0].input.Key, notBefore: expect.any(Date) } });
    expect(h.prisma.avatarCleanupJob.deleteMany).toHaveBeenCalledWith({ where: { objectKey: put[0].input.Key, attempts: 0, notBefore: { gt: expect.any(Date) } } });
    expect(h.prisma.$transaction).toHaveBeenCalledOnce();
  });

  it('refuses upload when the account is missing', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue(null);
    await expect(h.service.upload(UID, PHOTO)).rejects.toBeInstanceOf(NotFoundException);
    expect(commandsOf(PutObjectCommand)).toHaveLength(0);
  });

  it('refuses upload when R2 configuration is invalid', async () => {
    const h = harness();
    h.settings.R2_BUCKET = undefined;
    await expect(h.service.upload(UID, PHOTO))
      .rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(h.prisma.user.updateMany).not.toHaveBeenCalled();
  });

  it('does not alter the avatar record if R2 upload fails', async () => {
    const h = harness();
    mocks.send.mockRejectedValueOnce(new Error('R2 unavailable'));
    await expect(h.service.upload(UID, PHOTO)).rejects.toThrow('R2 unavailable');
    expect(h.prisma.user.updateMany).not.toHaveBeenCalled();
  });

  it('retains the orphan cleanup reservation if the database throws', async () => {
    const h = harness();
    h.prisma.user.updateMany.mockRejectedValue(new Error('DB unavailable'));
    await expect(h.service.upload(UID, PHOTO)).rejects.toThrow('DB unavailable');
    expect(commandsOf(PutObjectCommand)).toHaveLength(1);
    expect(commandsOf(DeleteObjectCommand)).toHaveLength(0);
    expect(h.prisma.avatarCleanupJob.create).toHaveBeenCalledWith({ data: { objectKey: commandsOf(PutObjectCommand)[0].input.Key, notBefore: expect.any(Date) } });
  });

  it('retains the orphan cleanup reservation after a concurrent update', async () => {
    const h = harness();
    h.prisma.user.updateMany.mockResolvedValue({ count: 0 });
    await expect(h.service.upload(UID, PHOTO)).rejects.toBeInstanceOf(ConflictException);
    expect(commandsOf(DeleteObjectCommand)).toHaveLength(0);
    expect(h.prisma.avatarCleanupJob.create).toHaveBeenCalledWith({ data: { objectKey: commandsOf(PutObjectCommand)[0].input.Key, notBefore: expect.any(Date) } });
  });

  it('replaces a stored avatar and queues only the old owned key', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ avatarUrl: GOOD_KEY });
    await expect(h.service.upload(UID, PHOTO)).resolves.toEqual({ url: URL });
    expect(h.prisma.user.updateMany).toHaveBeenCalledWith({
      where: { id: UID, avatarUrl: GOOD_KEY },
      data: { avatarUrl: expect.stringContaining(`avatars/${UID}/`) },
    });
    expect(commandsOf(DeleteObjectCommand)).toHaveLength(0);
    expect(h.prisma.avatarCleanupJob.upsert).toHaveBeenCalledWith({ where: { objectKey: GOOD_KEY }, create: { objectKey: GOOD_KEY, notBefore: expect.any(Date) }, update: {} });
  });

  it('never deletes a foreign key while replacing an avatar', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ avatarUrl: FOREIGN_KEY });
    await expect(h.service.upload(UID, PHOTO)).resolves.toEqual({ url: URL });
    expect(commandsOf(DeleteObjectCommand)).toHaveLength(0);
  });

  it('does not perform stale-object deletion inline after upload', async () => {
    const h = harness(); h.prisma.user.findUnique.mockResolvedValue({ avatarUrl: GOOD_KEY });
    mocks.send.mockResolvedValueOnce({}).mockRejectedValueOnce(new Error('cleanup failed'));
    await expect(h.service.upload(UID, PHOTO)).resolves.toEqual({ url: URL });
    expect(commandsOf(DeleteObjectCommand)).toHaveLength(0);
    expect(h.prisma.avatarCleanupJob.upsert).toHaveBeenCalledOnce();
  });

  it('does not commit an avatar pointer if signing fails', async () => {
    const h = harness(); mocks.signedUrl.mockRejectedValueOnce(new Error('cannot sign URL'));
    await expect(h.service.upload(UID, PHOTO)).rejects.toThrow('cannot sign URL');
    expect(h.prisma.user.updateMany).not.toHaveBeenCalled();
    expect(h.prisma.avatarCleanupJob.create).toHaveBeenCalledOnce();
    expect(h.prisma.$transaction).not.toHaveBeenCalled();
  });
});

describe('R2 avatar deletion', () => {
  it('rejects an absent account', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue(null);
    await expect(h.service.remove(UID)).rejects.toBeInstanceOf(NotFoundException);
  });

  it('returns null without doing writes if already deleted', async () => {
    const h = harness();
    await expect(h.service.remove(UID)).resolves.toEqual({ url: null });
    expect(h.prisma.user.updateMany).not.toHaveBeenCalled();
    expect(mocks.send).not.toHaveBeenCalled();
  });

  it('rejects concurrent deletion without touching object storage', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ avatarUrl: GOOD_KEY });
    h.prisma.user.updateMany.mockResolvedValue({ count: 0 });
    await expect(h.service.remove(UID)).rejects.toBeInstanceOf(ConflictException);
    expect(mocks.send).not.toHaveBeenCalled();
  });

  it('removes the DB pointer and the owned key', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ avatarUrl: GOOD_KEY });
    await expect(h.service.remove(UID)).resolves.toEqual({ url: null });
    expect(h.prisma.user.updateMany).toHaveBeenCalledWith({
      where: { id: UID, avatarUrl: GOOD_KEY }, data: { avatarUrl: null },
    });
    expect(commandsOf(DeleteObjectCommand)).toHaveLength(0);
    expect(h.prisma.avatarCleanupJob.upsert).toHaveBeenCalledWith({ where: { objectKey: GOOD_KEY }, create: { objectKey: GOOD_KEY, notBefore: expect.any(Date) }, update: {} });
  });

  it('clears legacy or foreign references without deleting unrelated objects', async () => {
    const h = harness();
    h.prisma.user.findUnique.mockResolvedValue({ avatarUrl: FOREIGN_KEY });
    await expect(h.service.remove(UID)).resolves.toEqual({ url: null });
    expect(commandsOf(DeleteObjectCommand)).toHaveLength(0);
    expect(h.prisma.avatarCleanupJob.upsert).not.toHaveBeenCalled();
  });

  it('does not require R2 availability to queue avatar deletion', async () => {
    const h = harness(); h.prisma.user.findUnique.mockResolvedValue({ avatarUrl: GOOD_KEY });
    mocks.send.mockRejectedValue(new Error('R2 cleanup failed'));
    await expect(h.service.remove(UID)).resolves.toEqual({ url: null });
    expect(commandsOf(DeleteObjectCommand)).toHaveLength(0);
    expect(h.prisma.avatarCleanupJob.upsert).toHaveBeenCalledOnce();
  });
});

describe('AvatarController routes', () => {
  it('delegates GET, POST, DELETE to the authenticated user ID', async () => {
    const api = {
      get: vi.fn().mockResolvedValue({ url: URL }),
      upload: vi.fn().mockResolvedValue({ url: URL }),
      remove: vi.fn().mockResolvedValue({ url: null }),
    };
    const controller = new AvatarController(api as never);
    const request = { user: { id: UID } };
    await expect(controller.get(request)).resolves.toEqual({ url: URL });
    await expect(controller.upload(request, PHOTO)).resolves.toEqual({ url: URL });
    await expect(controller.remove(request)).resolves.toEqual({ url: null });
    expect(api.get).toHaveBeenCalledWith(UID);
    expect(api.upload).toHaveBeenCalledWith(UID, PHOTO);
    expect(api.remove).toHaveBeenCalledWith(UID);
  });
});

// Final coverage closeout

describe('Final avatar upload authorization boundaries', () => {
  it('rejects an invalid owner reference before object upload', async () => {
    const h = harness();

    await expect(h.service.upload('invalid-user', PHOTO))
      .rejects.toBeInstanceOf(BadRequestException);

    expect(h.prisma.avatarCleanupJob.create).not.toHaveBeenCalled();
    expect(commandsOf(PutObjectCommand)).toHaveLength(0);
  });

  it('does not commit an expired cleanup reservation', async () => {
    const h = harness();

    h.prisma.avatarCleanupJob.deleteMany.mockResolvedValue({ count: 0 });

    await expect(h.service.upload(UID, PHOTO))
      .rejects.toBeInstanceOf(ConflictException);

    expect(h.prisma.user.updateMany).not.toHaveBeenCalled();
    expect(h.prisma.avatarCleanupJob.create).toHaveBeenCalledOnce();
  });
});
