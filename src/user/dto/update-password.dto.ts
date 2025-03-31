import { IsString, MinLength } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class UpdatePasswordDto {
  @ApiProperty({
    example: "oldpassword123",
    description: "Current password",
  })
  @IsString()
  currentPassword: string;

  @ApiProperty({
    example: "newpassword123",
    description: "New password (minimum 8 characters)",
  })
  @IsString()
  @MinLength(8)
  newPassword: string;
}
