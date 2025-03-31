import {
  Controller,
  Get,
  Param,
  Query,
  UseGuards,
  ParseUUIDPipe,
  Delete,
} from "@nestjs/common";
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from "@nestjs/swagger";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { SupabaseAuthGuard } from "../common/guards/supabase-auth.guard";
import { ReportService } from "../report/report.service";

@ApiTags("Report")
@Controller("report")
@UseGuards(SupabaseAuthGuard)
@ApiBearerAuth()
export class ReportController {
  constructor(private readonly reportService: ReportService) {}

  @Get(":scanId")
  @ApiOperation({ summary: "Get scan report" })
  @ApiResponse({ status: 200, description: "Scan report retrieved" })
  @ApiResponse({ status: 404, description: "Report not found" })
  async getScanReport(
    @Param("scanId", ParseUUIDPipe) scanId: string,
    @CurrentUser() user: any
  ) {
    const userId = user.id; // Extract userId from the user object
    return this.reportService.getScanReport(scanId, userId);
  }

  @Get()
  @ApiOperation({ summary: "Get paginated list of reports" })
  @ApiResponse({ status: 200, description: "Reports retrieved successfully" })
  async getReports(
    @Query("page") page: number = 1,
    @Query("limit") limit: number = 10,
    @CurrentUser() user: any
  ) {
    const userId = user.id; // Extract userId from the user object
    return this.reportService.getReports(userId, page, limit);
  }

  @Delete(":scanId")
  @ApiOperation({ summary: "Delete a scan report" })
  @ApiResponse({ status: 200, description: "Report deleted successfully" })
  @ApiResponse({ status: 404, description: "Report not found" })
  async deleteReport(
    @Param("scanId", ParseUUIDPipe) scanId: string,
    @CurrentUser() user: any
  ) {
    const userId = user.id; // Extract userId from the user object
    return this.reportService.deleteReport(scanId, userId);
  }
}
