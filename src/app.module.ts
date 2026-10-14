import {
  MiddlewareConsumer,
  Module,
  NestModule,
} from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AppLoggerService } from './common/logging/logger.service';
import { RequestContextMiddleware } from './common/middleware/request-context.middleware';
import { EducationModule } from './education/education.module';
import { HealthModule } from './health/health.module';
import { ObserveModule } from './observe';
import { ResourcesModule } from './resources/resources.module';
import { TreatmentsModule } from './treatments/treatments.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env.local',
    }),

    ObserveModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        appKey: config.getOrThrow<string>('OBSERVE_APP_KEY'),
        appSecret: config.getOrThrow<string>('OBSERVE_APP_SECRET'),
        serviceId: 'ted-education-mobile-api',
      }),
    }),

    HealthModule,
    EducationModule,
    TreatmentsModule,
    ResourcesModule,
  ],
  controllers: [AppController],
  providers: [AppService, AppLoggerService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(RequestContextMiddleware)
      .forRoutes('{*path}');
  }
}
