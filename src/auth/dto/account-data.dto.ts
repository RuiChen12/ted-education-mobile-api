import {
  Equals,
  IsIn,
  IsOptional,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class ExportAccountDataDto {
  @IsString()
  @MinLength(1)
  @MaxLength(72)
  currentPassword!: string;

  @IsOptional()
  @IsString()
  @Matches(/^[0-9]{6}$/)
  mfaCode?: string;
}

export class DeleteAccountDto extends ExportAccountDataDto {
  @Equals('DELETE')
  confirmation!: string;
}

export class GoogleDataChallengeDto {
  @IsString()
  @MinLength(20)
  @MaxLength(8192)
  idToken!: string;

  @IsIn(['EXPORT_DATA', 'DELETE_ACCOUNT'])
  action!: 'EXPORT_DATA' | 'DELETE_ACCOUNT';
}

export class GoogleExportAccountDataDto {
  @IsUUID('4')
  requestId!: string;

  @IsString()
  @Matches(/^[0-9]{8}$/)
  emailCode!: string;

  @IsOptional()
  @IsString()
  @Matches(/^[0-9]{6}$/)
  mfaCode?: string;
}

export class GoogleDeleteAccountDto extends GoogleExportAccountDataDto {
  @Equals('DELETE')
  confirmation!: string;
}
