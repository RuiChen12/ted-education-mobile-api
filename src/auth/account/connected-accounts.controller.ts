import {
  Body,
  Controller,
  Get,
  Header,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';

import { Throttle } from '@nestjs/throttler';

import {
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

import { JwtAuthGuard } from '../jwt/jwt-auth.guard';
import { ConnectedAccountsService } from './connected-accounts.service';

class VerifyConnectionDto {
  @IsString()
  @MinLength(1)
  @MaxLength(72)
  currentPassword!: string;

  @IsOptional()
  @IsString()
  @Matches(/^[0-9]{6}$/)
  mfaCode?: string;
}

class LinkGoogleDto extends VerifyConnectionDto {
  @IsString()
  @MinLength(20)
  @MaxLength(8192)
  idToken!: string;
}

class GooglePasswordChallengeDto {
  @IsString()
  @MinLength(20)
  @MaxLength(8192)
  idToken!: string;
}

class SetGooglePasswordDto {
  @IsUUID('4')
  requestId!: string;

  @IsString()
  @Matches(/^[0-9]{8}$/)
  emailCode!: string;

  @IsString()
  @MinLength(12)
  @MaxLength(72)
  newPassword!: string;

  @IsOptional()
  @IsString()
  @Matches(/^[0-9]{6}$/)
  mfaCode?: string;
}

type AuthRequest = {
  user: { id: string };
  sessionId: string;
};

@Controller('auth/connected-accounts')
@UseGuards(JwtAuthGuard)
export class ConnectedAccountsController {
  constructor(
    private readonly accounts: ConnectedAccountsService,
  ) {}

  @Get()
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 20, ttl: 60000 },
  })
  list(@Req() req: AuthRequest) {
    return this.accounts.list(req.user.id);
  }

  @Post('google/challenge')
  @HttpCode(200)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 3, ttl: 60000 },
  })
  requestGooglePasswordChallenge(
    @Req() req: AuthRequest,
    @Body() dto: GooglePasswordChallengeDto,
  ) {
    return this.accounts.requestGooglePasswordChallenge(
      req.user.id,
      req.sessionId,
      dto.idToken,
    );
  }

  @Post('google/set-password')
  @HttpCode(200)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 5, ttl: 60000 },
  })
  setGooglePassword(
    @Req() req: AuthRequest,
    @Body() dto: SetGooglePasswordDto,
  ) {
    return this.accounts.setGooglePassword(
      req.user.id,
      req.sessionId,
      dto.requestId,
      dto.emailCode,
      dto.newPassword,
      dto.mfaCode,
    );
  }

  @Post('google/link')
  @HttpCode(200)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 5, ttl: 60000 },
  })
  link(
    @Req() req: AuthRequest,
    @Body() dto: LinkGoogleDto,
  ) {
    return this.accounts.changeGoogle(
      req.user.id,
      req.sessionId,
      'link',
      dto.currentPassword,
      dto.mfaCode,
      dto.idToken,
    );
  }

  @Post('google/unlink')
  @HttpCode(200)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 5, ttl: 60000 },
  })
  unlink(
    @Req() req: AuthRequest,
    @Body() dto: VerifyConnectionDto,
  ) {
    return this.accounts.changeGoogle(
      req.user.id,
      req.sessionId,
      'unlink',
      dto.currentPassword,
      dto.mfaCode,
    );
  }
}