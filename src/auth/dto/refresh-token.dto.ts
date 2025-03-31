import { IsString } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class RefreshTokenDto {
  @ApiProperty({
    example: "your-refresh-token",
    description: "Refresh token to generate a new access token",
  })
  @IsString()
  refreshToken: string;
}
