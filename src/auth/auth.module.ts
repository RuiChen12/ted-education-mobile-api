import { SecurityLifecycleService } from './security/security-lifecycle.service';
import { AccountDataService } from './account/account-data.service';
import { SecurityActivityService } from './security/security-activity.service';
import { SecurityNotificationService } from '../notifications/security-notification.service';
import {
  JWT_ISSUER,
  JWT_AUDIENCE,
  JWT_ALGORITHM,
  JWT_ACCESS_DURATION,
} from './jwt/jwt.config';
import { JwtAuthGuard } from './jwt/jwt-auth.guard';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

import { PrismaModule } from '../prisma/prisma.module';
import { AuthController } from './auth.controller';
import { AvatarController } from './avatar/avatar.controller';
import { AvatarService } from './avatar/avatar.service';
import { AuthService } from './auth.service';
import { GoogleAuthService } from './google/google-auth.service';
import { MfaService } from './mfa/mfa.service';
import { MfaController } from './mfa/mfa.controller';
import { PasswordResetService } from './password/password-reset.service';
import { AuthSessionService } from './sessions/auth-session.service';
import { AuthSessionController } from './sessions/auth-session.controller';
import { EmailVerificationService } from './email/email-verification.service';
import { EmailChangeService } from './email/email-change.service';
import { EmailChangeController } from './email/email-change.controller';
import { ConnectedAccountsController } from './account/connected-accounts.controller';
import { AccountDataController } from './account/account-data.controller';
import { ConnectedAccountsService } from './account/connected-accounts.service';
import { GoogleActionChallengeService } from './google/google-action-challenge.service';

@Module({
  imports: [
    PrismaModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.getOrThrow<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: JWT_ACCESS_DURATION,
          issuer: JWT_ISSUER,
          audience: JWT_AUDIENCE,
          algorithm: JWT_ALGORITHM,
        },
      }),
    }),
  ],
  controllers: [AvatarController, AuthController, MfaController, AuthSessionController, EmailChangeController, ConnectedAccountsController, AccountDataController],
  providers: [SecurityLifecycleService, AccountDataService, AvatarService, AuthService, GoogleAuthService, PasswordResetService, EmailVerificationService, AuthSessionService, MfaService, JwtAuthGuard, EmailChangeService, ConnectedAccountsService, GoogleActionChallengeService, SecurityNotificationService, SecurityActivityService],
})
export class AuthModule {}
