import {
  IsBoolean, IsIn, IsInt, IsNumber, IsOptional,
  IsString, Length, Max, Min, ValidateIf
} from 'class-validator';
import { Gender } from '@prisma/client';

export class UpdateAccountDto {
  @ValidateIf((_object, value) => value !== undefined) @IsString() @Length(2,120)
  fullName?: string;

  @IsOptional() @IsIn(['MALE','FEMALE','PREFER_NOT_TO_SAY'])
  gender?: Gender | null;

  @ValidateIf((_object, value) => value !== undefined) @IsIn(['en','zh','ja','ko','es'])
  preferredLanguage?: string;

  @ValidateIf((_object, value) => value !== undefined) @IsNumber() @Min(1) @Max(2)
  fontScale?: number;

  @ValidateIf((_object, value) => value !== undefined) @IsBoolean()
  highContrast?: boolean;

  @ValidateIf((_object, value) => value !== undefined) @IsInt() @Min(0) @Max(3)
  onboardingStep?: number;

  @ValidateIf((_object, value) => value !== undefined) @IsBoolean()
  completeOnboarding?: boolean;
}
