import {
  Body,
  Controller,
  Header,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';

import { Throttle } from '@nestjs/throttler';

import {
  IsEmail,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

import { JwtAuthGuard } from '../jwt/jwt-auth.guard';
import { EmailChangeService } from './email-change.service';

class RequestEmailChangeDto {
  @IsEmail()
  @MaxLength(254)
  newEmail!: string;

  @IsString()
  @MinLength(1)
  @MaxLength(72)
  currentPassword!: string;

  @IsOptional()
  @IsString()
  @Matches(/^[0-9]{6}$/)
  mfaCode?: string;
}

class ConfirmEmailChangeDto {
  @IsUUID('4')
  requestId!: string;

  @IsString()
  @Matches(/^[0-9]{8}$/)
  oldCode!: string;

  @IsString()
  @Matches(/^[0-9]{8}$/)
  newCode!: string;
}

type AuthRequest = {
  user: { id: string };
  sessionId: string;
};

@Controller('auth/email-change')
@UseGuards(JwtAuthGuard)
export class EmailChangeController {
  constructor(
    private readonly emailChange: EmailChangeService,
  ) {}

  @Post('request')
  @Header('Cache-Control', 'private, no-store')
  @HttpCode(200)
  @Throttle({
    default: { limit: 5, ttl: 60000 },
  })
  request(
    @Req() req: AuthRequest,
    @Body() dto: RequestEmailChangeDto,
  ) {
    return this.emailChange.request(
      req.user.id,
      req.sessionId,
      dto.newEmail,
      dto.currentPassword,
      dto.mfaCode,
    );
  }

  @Post('confirm')
  @Header('Cache-Control', 'private, no-store')
  @HttpCode(200)
  @Throttle({
    default: { limit: 5, ttl: 60000 },
  })
  confirm(
    @Req() req: AuthRequest,
    @Body() dto: ConfirmEmailChangeDto,
  ) {
    return this.emailChange.confirm(
      req.user.id,
      req.sessionId,
      dto.requestId,
      dto.oldCode,
      dto.newCode,
    );
  }
}