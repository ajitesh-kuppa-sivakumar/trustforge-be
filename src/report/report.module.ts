import { Module } from "@nestjs/common";
import { ReportService } from "./report.service";
import { ReportController } from "./report.controller";
import { SupabaseService } from "../supabase/supabase.service";

@Module({
  controllers: [ReportController],
  providers: [ReportService, SupabaseService],
  exports: [ReportService],
})
export class ReportModule {}
