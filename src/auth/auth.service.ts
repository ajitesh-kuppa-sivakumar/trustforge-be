import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
} from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import { RegisterDto, LoginDto } from "./dto/auth.dto";
import { RefreshTokenDto } from "./dto/refresh-token.dto";

@Injectable()
export class AuthService {
  constructor(private readonly supabaseService: SupabaseService) {}

  async register(registerDto: RegisterDto) {
    const { email, password } = registerDto;

    const { data, error } = await this.supabaseService
      .getAdminClient()
      .auth.signUp({
        email,
        password,
      });

    if (error) {
      throw new BadRequestException(error.message);
    }

    return {
      message: "Registration successful",
      user: data.user,
    };
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    const { data, error } = await this.supabaseService
      .getAdminClient()
      .auth.signInWithPassword({
        email,
        password,
      });

    if (error) {
      throw new UnauthorizedException("Invalid credentials");
    }

    return {
      message: "Login successful",
      session: data.session,
      user: data.user,
    };
  }

  async loginWithGoogle() {
    const { data, error } = await this.supabaseService
      .getAdminClient()
      .auth.signInWithOAuth({
        provider: "google",
      });

    if (error) {
      throw new UnauthorizedException("Google authentication failed");
    }

    return data;
  }

  async logout(token: string) {
    const { error } = await this.supabaseService
      .getAdminClient()
      .auth.admin.signOut(token);

    if (error) {
      throw new UnauthorizedException("Logout failed");
    }

    return {
      message: "Logout successful",
    };
  }

  async refreshAccessToken(refreshTokenDto: RefreshTokenDto) {
    const { refreshToken } = refreshTokenDto;

    const { data, error } = await this.supabaseService
      .getAdminClient()
      .auth.refreshSession({ refresh_token: refreshToken });

    if (error) {
      throw new UnauthorizedException("Invalid or expired refresh token");
    }

    return {
      message: "Access token refreshed successfully",
      accessToken: data.session?.access_token,
      refreshToken: data.session?.refresh_token,
    };
  }
}
