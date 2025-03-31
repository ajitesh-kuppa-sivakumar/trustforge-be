import { Injectable } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";

interface Scan {
  scan_status: string;
  tf_score?: number;
  created_at: string;
  report_data?: {
    mobsf?: {
      appsec?: {
        high?: { title: string }[];
        medium?: { title: string }[];
        low?: { title: string }[];
      };
    };
    completed_at?: string;
  };
}

@Injectable()
export class DashboardService {
  constructor(private readonly supabaseService: SupabaseService) {}

  async getStatistics(userId: string) {
    const { data: scans, error } = await this.supabaseService
      .getAdminClient()
      .from("scans")
      .select("scan_status, tf_score, created_at, report_data")
      .eq("user_id", userId);

    if (error) {
      throw new Error("Failed to fetch scan data");
    }

    if (!scans || !Array.isArray(scans)) {
      throw new Error("Invalid scan data received");
    }

    const totalScans = scans.length;
    const completedScans = scans.filter(
      (scan) => scan.scan_status === "completed"
    ).length;
    const failedScans = scans.filter(
      (scan) => scan.scan_status === "failed"
    ).length;
    const averageTFScore =
      scans
        .filter((scan) => scan.scan_status === "completed")
        .reduce((sum, scan) => sum + (scan.tf_score || 0), 0) /
      (completedScans || 1);

    // Scans by Status
    const scansByStatus = scans.reduce(
      (acc, scan) => {
        acc[scan.scan_status] = (acc[scan.scan_status] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    // Top Vulnerabilities
    const vulnerabilities = scans
      .filter((scan: Scan) => scan.report_data?.mobsf?.appsec?.high)
      .flatMap(
        (scan: Scan) =>
          scan.report_data?.mobsf?.appsec?.high?.map(
            (vuln: { title: string }) => vuln.title
          ) || []
      );
    const topVulnerabilities = vulnerabilities.reduce(
      (acc, vuln) => {
        acc[vuln] = (acc[vuln] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    // Scan Trends (group by month)
    const scanTrends = scans.reduce(
      (acc, scan) => {
        const month = new Date(scan.created_at).toISOString().slice(0, 7); // YYYY-MM
        acc[month] = (acc[month] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    // Scan Duration Statistics
    const scanDurations = scans
      .filter((scan) => scan.scan_status === "completed" && scan.created_at)
      .map((scan) => {
        const createdAt = new Date(scan.created_at).getTime();
        const completedAt = new Date(
          scan.report_data?.completed_at || ""
        ).getTime();
        return completedAt - createdAt;
      });
    const averageScanDuration =
      scanDurations.reduce((sum, duration) => sum + duration, 0) /
      (scanDurations.length || 1);

    // Scan Success Rate
    const successRate = (completedScans / totalScans) * 100;

    // Vulnerability Severity Distribution
    const severityDistribution = scans.reduce(
      (acc, scan) => {
        const high = scan.report_data?.mobsf?.appsec?.high?.length || 0;
        const medium = scan.report_data?.mobsf?.appsec?.medium?.length || 0;
        const low = scan.report_data?.mobsf?.appsec?.low?.length || 0;
        acc.high += high;
        acc.medium += medium;
        acc.low += low;
        return acc;
      },
      { high: 0, medium: 0, low: 0 }
    );

    return {
      totalScans,
      completedScans,
      failedScans,
      averageTFScore: Math.round(averageTFScore * 100) / 100, // Round to 2 decimal places
      scansByStatus,
      topVulnerabilities,
      scanTrends,
      averageScanDuration: Math.round(averageScanDuration / 1000), // Convert to seconds
      successRate: Math.round(successRate * 100) / 100, // Round to 2 decimal places
      severityDistribution,
    };
  }
}
