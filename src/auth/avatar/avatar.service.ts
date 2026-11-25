import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
  type OnModuleInit,
  type OnModuleDestroy,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Prisma } from '@prisma/client';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { randomUUID } from 'node:crypto';
import sharp from 'sharp';

import { PrismaService } from '../../prisma/prisma.service';

type Upload = {
  buffer: Buffer;
  size: number;
  mimetype: string;
};

const MAX_FILE_SIZE = 3 * 1024 * 1024;
const SIGNED_URL_SECONDS = 300;
const CLEANUP_INTERVAL = 60000;
const UPLOAD_GRACE_PERIOD = 3600000;
const STORAGE_TIMEOUT = 30000;
const CLEANUP_BATCH = 20;

const UUID =
  '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';

const MANAGED_KEY = new RegExp(
  '^avatars/' + UUID + '/' + UUID + '\\.jpg$',
  'i',
);

@Injectable()
export class AvatarService
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger =
    new Logger(AvatarService.name);

  private cleanupTimer:
    ReturnType<typeof setInterval> | undefined;

  private cleaning = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  onModuleInit() {
    this.cleanupTimer = setInterval(() => {
      void this.drainCleanup();
    }, CLEANUP_INTERVAL);

    this.cleanupTimer.unref();
  }

  onModuleDestroy() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
  }

  private storage() {
    const account =
      this.config.get<string>('R2_ACCOUNT_ID')?.trim();

    const bucket =
      this.config.get<string>('R2_BUCKET')?.trim();

    const accessKeyId =
      this.config.get<string>('R2_ACCESS_KEY_ID')?.trim();

    const secretAccessKey =
      this.config.get<string>('R2_SECRET_ACCESS_KEY')?.trim();

    if (
      !account ||
      !bucket ||
      !accessKeyId ||
      !secretAccessKey ||
      !/^[a-f0-9]{32}$/i.test(account)
    ) {
      throw new ServiceUnavailableException(
        'Avatar storage is not configured.',
      );
    }

    return {
      bucket,
      client: new S3Client({
        region: 'auto',
        endpoint:
          'https://' +
          account +
          '.r2.cloudflarestorage.com',
        credentials: {
          accessKeyId,
          secretAccessKey,
        },
        maxAttempts: 2,
      }),
    };
  }

  private validKey(
    id: string,
    key: string | null,
  ): key is string {
    return (
      typeof key === 'string' &&
      MANAGED_KEY.test(key) &&
      key.startsWith('avatars/' + id + '/')
    );
  }

  private async signed(
    id: string,
    key: string,
  ) {
    if (!this.validKey(id, key)) {
      throw new BadRequestException(
        'Invalid avatar reference.',
      );
    }

    const { client, bucket } = this.storage();

    try {
      return await getSignedUrl(
        client,
        new GetObjectCommand({
          Bucket: bucket,
          Key: key,
        }),
        {
          expiresIn: SIGNED_URL_SECONDS,
        },
      );
    } finally {
      client.destroy();
    }
  }

  private async queueRetired(
    tx: Prisma.TransactionClient,
    key: string,
  ) {
    await tx.avatarCleanupJob.upsert({
      where: {
        objectKey: key,
      },
      create: {
        objectKey: key,
        notBefore: new Date(),
      },
      update: {},
    });
  }

  private retryDelay(attempts: number) {
    return Math.min(
      24 * 60 * 60 * 1000,
      Math.max(
        5 * 60 * 1000,
        60000 * Math.pow(
          2,
          Math.min(attempts, 10),
        ),
      ),
    );
  }

  private async drainCleanup() {
    if (this.cleaning) return;

    this.cleaning = true;

    try {
      const jobs =
        await this.prisma.avatarCleanupJob.findMany({
          where: {
            notBefore: {
              lte: new Date(),
            },
          },
          orderBy: {
            notBefore: 'asc',
          },
          take: CLEANUP_BATCH,
        });

      for (const job of jobs) {
        try {
          if (!MANAGED_KEY.test(job.objectKey)) {
            this.logger.error(
              'Invalid avatar cleanup job requires review.',
            );

            await this.prisma.avatarCleanupJob.updateMany({
              where: {
                objectKey: job.objectKey,
                attempts: job.attempts,
              },
              data: {
                notBefore: new Date(
                  Date.now() + 86400000,
                ),
              },
            });

            continue;
          }

          const nextAttempt = job.attempts + 1;

          const claimed =
            await this.prisma.avatarCleanupJob.updateMany({
              where: {
                objectKey: job.objectKey,
                attempts: job.attempts,
                notBefore: job.notBefore,
              },
              data: {
                attempts: {
                  increment: 1,
                },
                notBefore: new Date(
                  Date.now() +
                  this.retryDelay(nextAttempt),
                ),
              },
            });

          if (claimed.count !== 1) {
            continue;
          }

          // Never delete an object that is still referenced.
          const active =
            await this.prisma.user.findFirst({
              where: {
                avatarUrl: job.objectKey,
              },
              select: {
                id: true,
              },
            });

          if (active) {
            continue;
          }

          const { client, bucket } = this.storage();

          try {
            await client.send(
              new DeleteObjectCommand({
                Bucket: bucket,
                Key: job.objectKey,
              }),
              {
                abortSignal:
                  AbortSignal.timeout(STORAGE_TIMEOUT),
              },
            );
          } finally {
            client.destroy();
          }

          await this.prisma.avatarCleanupJob.deleteMany({
            where: {
              objectKey: job.objectKey,
              attempts: nextAttempt,
            },
          });
        } catch {
          // The durable job remains available for retry.
          this.logger.warn(
            'Avatar cleanup deferred for retry.',
          );
        }
      }
    } catch {
      this.logger.warn(
        'Avatar cleanup queue is temporarily unavailable.',
      );
    } finally {
      this.cleaning = false;
    }
  }

  async get(id: string) {
    const user =
      await this.prisma.user.findUnique({
        where: { id },
        select: {
          avatarUrl: true,
        },
      });

    if (!user) {
      throw new NotFoundException(
        'Account not found.',
      );
    }

    return {
      url: this.validKey(id, user.avatarUrl)
        ? await this.signed(id, user.avatarUrl)
        : null,
    };
  }

  async upload(
    id: string,
    file?: Upload,
  ) {
    if (
      !file?.buffer?.length ||
      file.size <= 0 ||
      file.size > MAX_FILE_SIZE ||
      file.buffer.length > MAX_FILE_SIZE
    ) {
      throw new BadRequestException(
        'Choose a photo under 3 MB.',
      );
    }

    let jpeg: Buffer;

    try {
      const image = sharp(file.buffer, {
        limitInputPixels: 20000000,
        failOn: 'error',
      });

      const meta = await image.metadata();

      if (
        !meta.format ||
        !['jpeg', 'png', 'webp'].includes(meta.format)
      ) {
        throw new Error('Unsupported format');
      }

      jpeg = await image
        .rotate()
        .resize(256, 256, {
          fit: 'cover',
        })
        .jpeg({
          quality: 82,
          mozjpeg: true,
        })
        .toBuffer();
    } catch {
      throw new BadRequestException(
        'Use a valid JPEG, PNG or WebP photo.',
      );
    }

    const user =
      await this.prisma.user.findUnique({
        where: { id },
        select: {
          avatarUrl: true,
        },
      });

    if (!user) {
      throw new NotFoundException(
        'Account not found.',
      );
    }

    const key =
      'avatars/' +
      id +
      '/' +
      randomUUID() +
      '.jpg';

    if (!this.validKey(id, key)) {
      throw new BadRequestException(
        'Invalid avatar reference.',
      );
    }

    // Register the potential orphan before touching R2.
    await this.prisma.avatarCleanupJob.create({
      data: {
        objectKey: key,
        notBefore: new Date(
          Date.now() + UPLOAD_GRACE_PERIOD,
        ),
      },
    });

    const { client, bucket } = this.storage();

    try {
      await client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: key,
          Body: jpeg,
          ContentType: 'image/jpeg',
          CacheControl: 'private, no-store',
        }),
        {
          abortSignal:
            AbortSignal.timeout(STORAGE_TIMEOUT),
        },
      );
    } finally {
      client.destroy();
    }

    // Generate the URL before committing the database update.
    const url = await this.signed(id, key);

    await this.prisma.$transaction(async tx => {
      const reservation =
        await tx.avatarCleanupJob.deleteMany({
          where: {
            objectKey: key,
            attempts: 0,
            notBefore: {
              gt: new Date(),
            },
          },
        });

      if (reservation.count !== 1) {
        throw new ConflictException(
          'Avatar upload expired. Retry.',
        );
      }

      const updated = await tx.user.updateMany({
        where: {
          id,
          avatarUrl: user.avatarUrl,
        },
        data: {
          avatarUrl: key,
        },
      });

      if (updated.count !== 1) {
        throw new ConflictException(
          'Avatar changed elsewhere. Retry.',
        );
      }

      if (this.validKey(id, user.avatarUrl)) {
        await this.queueRetired(
          tx,
          user.avatarUrl,
        );
      }
    });

    return { url };
  }

  async remove(id: string) {
    const user =
      await this.prisma.user.findUnique({
        where: { id },
        select: {
          avatarUrl: true,
        },
      });

    if (!user) {
      throw new NotFoundException(
        'Account not found.',
      );
    }

    if (!user.avatarUrl) {
      return { url: null };
    }

    await this.prisma.$transaction(async tx => {
      const result = await tx.user.updateMany({
        where: {
          id,
          avatarUrl: user.avatarUrl,
        },
        data: {
          avatarUrl: null,
        },
      });

      if (result.count !== 1) {
        throw new ConflictException(
          'Avatar changed elsewhere. Retry.',
        );
      }

      if (this.validKey(id, user.avatarUrl)) {
        await this.queueRetired(
          tx,
          user.avatarUrl,
        );
      }
    });

    return { url: null };
  }
}
