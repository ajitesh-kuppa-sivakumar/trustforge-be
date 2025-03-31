import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Logger,
  UnauthorizedException,
} from "@nestjs/common";
import { SupabaseService } from "../../supabase/supabase.service";

@Injectable()
export class SupabaseAuthGuard implements CanActivate {
  private readonly logger = new Logger(SupabaseAuthGuard.name);

  constructor(private supabaseService: SupabaseService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      this.logger.debug("No token found in the request headers");
      throw new UnauthorizedException("Access token is missing");
    }

    try {
      const {
        data: { user },
        error,
      } = await this.supabaseService.getAdminClient().auth.getUser(token);

      if (error) {
        this.logger.debug(`Error retrieving user: ${error.message}`);
        throw new UnauthorizedException("Invalid or expired access token");
      }

      if (!user) {
        this.logger.debug("User not found");
        throw new UnauthorizedException("User not found");
      }

      request.user = user;
      request.userId = user.id; // Add userId to the request object
      return true;
    } catch (err) {
      this.logger.error("Error in authentication guard", err);
      throw new UnauthorizedException("Authentication failed");
    }
  }

  private extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(" ") ?? [];
    return type === "Bearer" ? token : undefined;
  }
}
