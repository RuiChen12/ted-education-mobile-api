
import {
  Controller, Delete, Get, Header, HttpCode, Post,
  Req, UploadedFile, UseGuards, UseInterceptors
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { Throttle } from '@nestjs/throttler';
import { JwtAuthGuard } from '../jwt/jwt-auth.guard';
import { AvatarService } from './avatar.service';

type AuthRequest = { user: { id: string } };
type Upload = { buffer: Buffer; size: number; mimetype: string };

@Controller('auth/avatar')
@UseGuards(JwtAuthGuard)
export class AvatarController {
  constructor(private readonly avatars: AvatarService) {}

  @Get()
  @Header('Cache-Control', 'private, no-store')
  get(@Req() req: AuthRequest) {
    return this.avatars.get(req.user.id);
  }

  @Post()
  @HttpCode(200)
  @Throttle({ default: { limit: 6, ttl: 60000 } })
  @UseInterceptors(FileInterceptor('file', {
    limits: {
      fileSize: 3 * 1024 * 1024,
      files: 1,
      fields: 0,
      parts: 1
    }
  }))
  upload(
    @Req() req: AuthRequest,
    @UploadedFile() file?: Upload
  ) {
    return this.avatars.upload(req.user.id, file);
  }

  @Delete()
  @HttpCode(200)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  remove(@Req() req: AuthRequest) {
    return this.avatars.remove(req.user.id);
  }
}
