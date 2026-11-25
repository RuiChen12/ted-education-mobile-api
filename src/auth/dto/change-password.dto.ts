import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength
} from 'class-validator';

export class ChangePasswordDto {
  @ApiProperty({ writeOnly: true })
  @IsString()
  @MinLength(1)
  @MaxLength(72)
  currentPassword!: string;

  @ApiProperty({
    writeOnly: true,
    minLength: 12,
    maxLength: 72
  })
  @IsString()
  @MinLength(12)
  @MaxLength(72)
  newPassword!: string;

  @ApiPropertyOptional({
    writeOnly: true,
    description: 'Required when authenticator MFA is enabled.',
  })
  @IsOptional()
  @IsString()
  @Matches(/^[0-9]{6}$/)
  mfaCode?: string;
}
