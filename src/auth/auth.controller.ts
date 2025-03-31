import {
  Controller,
  Post,
  Body,
  Headers,
  UseGuards,
  HttpCode,
  HttpStatus,
} from "@nestjs/common";
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from "@nestjs/swagger";
import { AuthService } from "./auth.service";
import { RegisterDto, LoginDto } from "./dto/auth.dto";
import { SupabaseAuthGuard } from "../common/guards/supabase-auth.guard";
import { RefreshTokenDto } from "./dto/refresh-token.dto";

@ApiTags("Authentication")
@Controller("auth")
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("register")
  @ApiOperation({ summary: "Register a new user" })
  @ApiResponse({ status: 201, description: "User successfully registered" })
  @ApiResponse({ status: 400, description: "Bad request" })
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post("login")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Login with email and password" })
  @ApiResponse({ status: 200, description: "User successfully logged in" })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post("google")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Login with Google" })
  @ApiResponse({
    status: 200,
    description: "User successfully logged in with Google",
  })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  async googleLogin() {
    return this.authService.loginWithGoogle();
  }

  @Post("logout")
  @UseGuards(SupabaseAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Logout user" })
  @ApiResponse({ status: 200, description: "User successfully logged out" })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  async logout(@Headers("authorization") auth: string) {
    const token = auth.split(" ")[1];
    return this.authService.logout(token);
  }

  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Refresh access token" })
  @ApiResponse({
    status: 200,
    description: "Access token refreshed successfully",
  })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  async refresh(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshAccessToken(refreshTokenDto);
  }
}
