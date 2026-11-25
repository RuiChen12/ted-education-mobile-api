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
import { JwtAuthGuard } from '../jwt/jwt-auth.guard';

import {
  AccountDataService,
  type AuthRequest,
} from './account-data.service';

import {
  ExportAccountDataDto,
  DeleteAccountDto,
  GoogleDataChallengeDto,
  GoogleExportAccountDataDto,
  GoogleDeleteAccountDto,
} from '../dto/account-data.dto';

@Controller('auth/account-data')
@UseGuards(JwtAuthGuard)
export class AccountDataController {
  constructor(
    private readonly accountData: AccountDataService,
  ) {}

  @Post('export')
  @HttpCode(200)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 3, ttl: 60000 },
  })
  async exportAccount(
    @Req() req: AuthRequest,
    @Body() dto: ExportAccountDataDto,
  ) {
    return this.accountData.exportAccount(req, dto);
  }

  @Post('delete')
  @HttpCode(200)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 3, ttl: 60000 },
  })
  async deleteAccount(
    @Req() req: AuthRequest,
    @Body() dto: DeleteAccountDto,
  ) {
    return this.accountData.deleteAccount(req, dto);
  }

  @Post('google/challenge')
  @HttpCode(200)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 3, ttl: 60000 },
  })
  async requestGoogleDataChallenge(
    @Req() req: AuthRequest,
    @Body() dto: GoogleDataChallengeDto,
  ) {
    return this.accountData.requestGoogleDataChallenge(req, dto);
  }

  @Post('google/export')
  @HttpCode(200)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 3, ttl: 60000 },
  })
  async exportGoogleAccount(
    @Req() req: AuthRequest,
    @Body() dto: GoogleExportAccountDataDto,
  ) {
    return this.accountData.exportGoogleAccount(req, dto);
  }

  @Post('google/delete')
  @HttpCode(200)
  @Header('Cache-Control', 'private, no-store')
  @Throttle({
    default: { limit: 3, ttl: 60000 },
  })
  async deleteGoogleAccount(
    @Req() req: AuthRequest,
    @Body() dto: GoogleDeleteAccountDto,
  ) {
    return this.accountData.deleteGoogleAccount(req, dto);
  }
}
