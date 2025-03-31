import { Controller, Get, UseGuards } from "@nestjs/common";
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
} from "@nestjs/swagger";
import { SupabaseAuthGuard } from "../common/guards/supabase-auth.guard";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { DashboardService } from "./dashboard.service";

@ApiTags("Dashboard")
@Controller("dashboard")
@UseGuards(SupabaseAuthGuard)
@ApiBearerAuth()
export class DashboardController {
  constructor(private readonly dashboardService: DashboardService) {}

  @Get("")
  @ApiOperation({ summary: "Get dashboard statistics" })
  @ApiResponse({
    status: 200,
    description: "Statistics retrieved successfully",
  })
  async getStatistics(@CurrentUser() user: any) {
    return this.dashboardService.getStatistics(user.id);
  }
}
