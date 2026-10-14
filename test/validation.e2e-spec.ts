
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import type { App } from 'supertest/types';

import { configureHttp } from '../src/common/configure-http';
import { EducationModule } from '../src/education/education.module';
import { HealthModule } from '../src/health/health.module';
import { ResourcesModule } from '../src/resources/resources.module';
import { TreatmentsModule } from '../src/treatments/treatments.module';

describe('API-004 Request Validation (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        HealthModule,
        EducationModule,
        TreatmentsModule,
        ResourcesModule,
      ],
    }).compile();

    app = moduleRef.createNestApplication();

    configureHttp(app);

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  const collections = [
    'education',
    'treatments',
    'resources',
  ];

  describe.each(collections)('%s collection', (endpoint) => {
    it('accepts requests without query parameters', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/${endpoint}`)
        .expect(200);
    });

    it('accepts supported language', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/${endpoint}?language=en`)
        .expect(200);
    });

    it('rejects unsupported language', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/${endpoint}?language=invalid`)
        .expect(400);
    });

    it('rejects unknown query fields', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/${endpoint}?unknownField=test`)
        .expect(400);
    });

    it('rejects long search values', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/${endpoint}`)
        .query({ search: 'a'.repeat(101) })
        .expect(400);
    });

    it('rejects empty category', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/${endpoint}?category=`)
        .expect(400);
    });

    it('returns 404 for nonexistent IDs', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/${endpoint}/not-real`)
        .expect(404);
    });
  });

  describe('Health endpoint', () => {
    it('returns 200 OK', async () => {
      await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);
    });
  });
});
