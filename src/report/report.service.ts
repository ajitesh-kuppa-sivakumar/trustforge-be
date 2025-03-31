import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";

@Injectable()
export class ReportService {
  constructor(private readonly supabaseService: SupabaseService) {}

  async getScanReport(scanId: string, userId: string) {
    const { data, error } = await this.supabaseService
      .getAdminClient()
      .from("scans")
      .select("*")
      .eq("scan_id", scanId)
      .eq("user_id", userId)
      .single();

    if (error || !data) {
      throw new NotFoundException("Report not found");
    }

    if (data.scan_status !== "completed") {
      throw new BadRequestException("Scan is not completed yet");
    }

    // Exclude specific keys from mobsf
    const excludedKeys = ["strings", "files", "urls", "sbom", "logs"];
    const mobsf = data.report_data?.mobsf
      ? Object.fromEntries(
          Object.entries(data.report_data.mobsf).filter(
            ([key]) => !excludedKeys.includes(key)
          )
        )
      : null;

    // Transform the data into the desired format
    return {
      scanId: data.scan_id,
      fileName: data.file_name,
      tfScore: data.tf_score,
      mobsf,
      virustotal: data.report_data?.virustotal || null,
      metadefender: data.report_data?.metadefender || null,
      hybridAnalysis: data.report_data?.hybridAnalysis || null,
    };
  }

  async getReports(userId: string, page: number, limit: number) {
    const offset = (page - 1) * limit;

    const { data, error, count } = await this.supabaseService
      .getAdminClient()
      .from("scans")
      .select("scan_id, file_name, scan_status, created_at", { count: "exact" })
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      throw new BadRequestException("Failed to fetch reports");
    }

    return {
      total: count,
      page,
      limit,
      data: data.map((record) => ({
        scanId: record.scan_id,
        fileName: record.file_name,
        scanStatus: record.scan_status,
        date: record.created_at,
      })),
    };
  }

  async deleteReport(scanId: string, userId: string) {
    const { data, error } = await this.supabaseService
      .getAdminClient()
      .from("scans")
      .delete()
      .eq("scan_id", scanId)
      .eq("user_id", userId)
      .select("scan_id") // Ensure the deleted record is returned
      .single();

    if (error) {
      throw new BadRequestException("Failed to delete the report");
    }

    if (!data) {
      throw new NotFoundException("Report not found or already deleted");
    }

    return {
      message: "Report deleted successfully",
      scanId: data.scan_id,
    };
  }
}
