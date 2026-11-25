import { Query } from '@nestjs/common';
import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  Param,
  ParseUUIDPipe,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { IsString, Matches } from 'class-validator';

import { AuthSessionService } from './auth-session.service';
import { JwtAuthGuard } from '../jwt/jwt-auth.guard';
import { REFRESH_TOKEN_PATTERN } from '../jwt/jwt.config';

class RefreshDto {
  @IsString()
  @Matches(REFRESH_TOKEN_PATTERN)
  refreshToken!: string;
}

@Controller('auth')
export class AuthSessionController {
  constructor(
    private readonly sessions: AuthSessionService,
  ) {}

  @Post('refresh')
  @HttpCode(200)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 10, ttl: 60000 },
  })
  refresh(@Body() dto: RefreshDto) {
    return this.sessions.refresh(dto.refreshToken);
  }

  @Post('logout')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  @Throttle({
    default: {
      limit: 10,
      ttl: 60000,
    },
  })
  logout(
    @Req()
    req: {
      user: { id: string };
      sessionId: string;
    },
  ) {
    return this.sessions.logoutCurrent(
      req.user.id,
      req.sessionId,
    );
  }

  @Get('security-activity')
  @UseGuards(JwtAuthGuard)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 20, ttl: 60000 },
  })
  listSecurityActivity(
    @Req() req: { user: { id: string } },
    @Query('cursor') cursor?: string,
  ) {
    return this.sessions.listSecurityActivity(
      req.user.id,
      cursor,
    );
  }

  @Get('sessions')
  @UseGuards(JwtAuthGuard)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 20, ttl: 60000 },
  })
  listSessions(
    @Req()
    req: {
      user: { id: string };
      sessionId: string;
    },
  ) {
    return this.sessions.listSessions(
      req.user.id,
      req.sessionId,
    );
  }

  @Delete('sessions/:id')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 10, ttl: 60000 },
  })
  revokeSession(
    @Req()
    req: {
      user: { id: string };
      sessionId: string;
    },
    @Param('id', new ParseUUIDPipe({ version: '4' }))
    id: string,
  ) {
    return this.sessions.revokeSession(
      req.user.id,
      req.sessionId,
      id.toLowerCase(),
    );
  }

  @Post('logout-all')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  logoutAll(
    @Req() req: {
      user: { id: string };
      sessionId: string;
    },
  ) {
    return this.sessions.logoutAll(
      req.user.id,
      req.sessionId,
    );
  }
}
