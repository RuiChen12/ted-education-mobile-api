import { Body, Controller, Get, Header, HttpCode, Post, Req, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { IsString, Matches, MaxLength } from 'class-validator';
import { MfaService } from './mfa.service';
import { JwtAuthGuard } from '../jwt/jwt-auth.guard';

class CodeDto {
  @IsString()
  @Matches(/^([0-9]{6}|[A-Fa-f0-9]{8}-[A-Fa-f0-9]{8})$/)
  code!: string;
}
class TotpOnlyDto {
  @IsString()
  @Matches(/^[0-9]{6}$/)
  code!: string;
}

class VerifyDto extends CodeDto {
  @IsString()
  @MaxLength(4096)
  challengeToken!: string;
}

type AuthRequest = {
  user: { id: string; email: string };
  sessionId: string;
};

@Controller('auth/mfa')
export class MfaController {
  constructor(private readonly mfa: MfaService) {}

  @Get('status')
  @Header('Cache-Control', 'private, no-store')
  @UseGuards(JwtAuthGuard)
  status(@Req() req: AuthRequest) { return this.mfa.status(req.user.id); }

  @Post('setup')
  @Header('Cache-Control', 'private, no-store')
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  setup(@Req() req: AuthRequest) { return this.mfa.setup(req.user.id, req.sessionId); }

  @Post('enable')
  @Header('Cache-Control', 'private, no-store')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  enable(@Req() req: AuthRequest, @Body() dto: CodeDto) {
    return this.mfa.enable(req.user.id, dto.code, req.sessionId);
  }

  @Post('verify')
  @Header('Cache-Control', 'private, no-store')
  @HttpCode(200)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  verify(@Body() dto: VerifyDto) { return this.mfa.verifyChallenge(dto.challengeToken, dto.code); }

  @Post('recovery/regenerate')
  @Header('Cache-Control', 'private, no-store')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  regenerateRecoveryCodes(@Req() req: AuthRequest, @Body() dto: TotpOnlyDto) {
    return this.mfa.regenerateRecoveryCodes(req.user.id, dto.code, req.sessionId);
  }

  @Post('disable')
  @Header('Cache-Control', 'private, no-store')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  disable(@Req() req: AuthRequest, @Body() dto: CodeDto) {
    return this.mfa.disable(req.user.id, dto.code, req.sessionId);
  }
}
