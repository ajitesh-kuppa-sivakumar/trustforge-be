import {
  IsOptional,
  IsString,
  IsEmail,
  MinLength,
  IsUrl,
} from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class UpdateUserDto {
  @ApiProperty({
    example: "newuser@example.com",
    description: "New email address",
    required: false,
  })
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiProperty({
    example: "John Doe",
    description: "New name",
    required: false,
  })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiProperty({
    example: "newpassword123",
    description: "New password (minimum 8 characters)",
    required: false,
  })
  @IsOptional()
  @IsString()
  @MinLength(8)
  password?: string;

  @ApiProperty({
    example: "https://example.com/profile.jpg",
    description: "New profile picture URL",
    required: false,
  })
  @IsOptional()
  @IsUrl()
  picture?: string;
}
