import { Process, Processor } from "@nestjs/bull";
import { Logger } from "@nestjs/common";
import { Job } from "bull";
import { SupabaseService } from "../supabase/supabase.service";
import { promises as fsPromises } from "fs";
import * as fs from "fs";
import * as path from "path";
import axios from "axios";
import { PDFDocument, rgb, StandardFonts, RGB } from "pdf-lib";
import fontkit from "@pdf-lib/fontkit";
import * as FormData from "form-data";
import * as dotenv from "dotenv";
import * as qs from "querystring";
import { fileTypeFromBuffer } from "file-type";
import { createHash } from "crypto";

dotenv.config();

@Processor("scan")
export class ScanProcessor {
  private readonly logger = new Logger(ScanProcessor.name);
  private readonly mobSFUrl = process.env.MOBSF_API_URL;
  private readonly mobSFApiKey = process.env.MOBSF_API_KEY;
  private readonly virusTotalUrl = "https://www.virustotal.com/api/v3/files";
  private readonly virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;
  private readonly metaDefenderUrl = "https://api.metadefender.com/v4/file";
  private readonly metaDefenderApiKey = process.env.METADEFENDER_API_KEY;
  private readonly hybridAnalysisUrl = "https://www.hybrid-analysis.com/api/v2";
  private readonly hybridAnalysisApiKey = process.env.HYBRID_ANALYSIS_API_KEY;

  constructor(private readonly supabaseService: SupabaseService) {}

  @Process("process")
  async processScan(
    job: Job<{ scanId: string; userId: string; filePath: string }>
  ) {
    try {
      this.logger.log(`Processing scan job: ${job.id}`);
      const { scanId, userId, filePath } = job.data;
      if (!scanId) {
        throw new Error("Invalid scanId");
      }
      const tempDir = path.join(process.cwd(), "temp", scanId);
      await fsPromises.mkdir(tempDir, { recursive: true });

      const relativeFilePath = filePath.replace(/^app-uploads\//, "");
      const { data } = this.supabaseService
        .getAdminClient()
        .storage.from("app-uploads")
        .getPublicUrl(relativeFilePath);

      if (!data || !data.publicUrl) {
        this.logger.error("Failed to get public URL for file");
        throw new Error("Failed to get public URL for file");
      }

      const publicUrl = data.publicUrl;
      const response = await axios.get(publicUrl, {
        responseType: "arraybuffer",
      });
      if (response.status !== 200) {
        this.logger.error("Failed to download file");
        throw new Error("Failed to download file");
      }

      const localFilePath = path.join(tempDir, path.basename(filePath));
      await fsPromises.writeFile(localFilePath, response.data);

      this.logger.log("File downloaded and saved locally");

      const mobsfResult = await this.runMobSFScan(localFilePath);

      let virusTotalResult, metaDefenderResult, hybridAnalysisResult;

      try {
        virusTotalResult = await this.runVirusTotalScan(localFilePath);
        this.logger.log("VirusTotal scan completed");
      } catch (vtError) {
        this.logger.warn(`VirusTotal scan failed: ${vtError.message}`);
        virusTotalResult = { error: vtError.message };
      }

      try {
        metaDefenderResult = await this.runMetaDefenderScan(localFilePath);
        this.logger.log("MetaDefender scan completed");
      } catch (mdError) {
        this.logger.warn(`MetaDefender scan failed: ${mdError.message}`);
        metaDefenderResult = { error: mdError.message };
      }

      try {
        hybridAnalysisResult = await this.runHybridAnalysisScan(localFilePath);
        this.logger.log("Hybrid Analysis scan completed");
      } catch (haError) {
        this.logger.warn(`Hybrid Analysis scan failed: ${haError.message}`);
        hybridAnalysisResult = { error: haError.message };
      }

      // Calculate the TF score using the results of all scans
      const tfScore = this.calculateTFScore({
        mobsf: mobsfResult,
        virustotal: virusTotalResult,
        metadefender: metaDefenderResult,
        hybridAnalysis: hybridAnalysisResult,
      });

      // Combine the results for further processing
      const combinedResults = {
        mobsf: mobsfResult,
        virustotal: virusTotalResult,
        metadefender: metaDefenderResult,
        hybridAnalysis: hybridAnalysisResult,
      };

      // Generate the PDF report using the combined results
      const pdfBuffer = await this.generatePDFReport({
        scanId,
        fileName: path.basename(filePath),
        tfScore,
        findings: combinedResults,
        reportData: mobsfResult,
      });

      const reportFileName = `${path.basename(filePath, path.extname(filePath))}_report.pdf`;
      const pdfPath = `${userId}/${scanId}/${reportFileName}`;

      const { error: pdfUploadError } = await this.supabaseService
        .getAdminClient()
        .storage.from("app-pdf-reports")
        .upload(pdfPath, pdfBuffer);

      if (pdfUploadError) {
        this.logger.error("Failed to upload PDF report");
        throw new Error("Failed to upload PDF report");
      }

      const recommendations = this.generateRecommendations(combinedResults);

      if (!scanId) {
        throw new Error("Invalid scanId");
      }

      const updateData = {
        scan_status: "completed",
        tf_score: tfScore || 0,
        pdf_report_url: pdfPath || "",
        report_data: combinedResults || {},
      };

      const { error: updateError } = await this.supabaseService
        .getAdminClient()
        .from("scans")
        .update(updateData)
        .eq("scan_id", scanId);

      if (updateError) {
        this.logger.error("Supabase update error details:", updateError);
        throw new Error("Failed to update scan record");
      }

      await fsPromises.rm(tempDir, { recursive: true, force: true });
      this.logger.log(`Scan job ${job.id} completed successfully`);
    } catch (error) {
      this.logger.error(`Scan processing failed: ${error.message}`);
      await this.supabaseService
        .getAdminClient()
        .from("scans")
        .update({ scan_status: "failed" })
        .eq("scan_id", job.data.scanId);
      throw error;
    }
  }

  private async generatePDFReport(data: {
    scanId: string;
    fileName: string;
    tfScore: number;
    findings: any;
    reportData: any;
  }): Promise<Buffer> {
    const pdfDoc = await PDFDocument.create();
    pdfDoc.registerFontkit(fontkit);

    let font, boldFont;
    try {
      const fontPath = path.resolve(
        process.cwd(),
        "src",
        "assets",
        "fonts",
        "NotoSans-Regular.ttf"
      );
      const boldFontPath = path.resolve(
        process.cwd(),
        "src",
        "assets",
        "fonts",
        "NotoSans-Bold.ttf"
      );

      if (fs.existsSync(fontPath)) {
        const fontBytes = await fsPromises.readFile(fontPath);
        font = await pdfDoc.embedFont(fontBytes);
      } else {
        throw new Error("Regular font file not found");
      }

      if (fs.existsSync(boldFontPath)) {
        const boldFontBytes = await fsPromises.readFile(boldFontPath);
        boldFont = await pdfDoc.embedFont(boldFontBytes);
      } else {
        boldFont = font;
      }
    } catch (error) {
      this.logger.error(`Error loading custom fonts: ${error.message}`);
      font = await pdfDoc.embedFont(StandardFonts.Helvetica);
      boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
    }

    const createNewPage = () => {
      const page = pdfDoc.addPage([600, 800]);
      const { height } = page.getSize();

      page.drawText("TrustForge Security Report", {
        x: 50,
        y: height - 50,
        size: 16,
        font: boldFont,
      });

      return { page, yPos: height - 80 };
    };

    let { page, yPos } = createNewPage();
    const { width, height } = page.getSize();

    page.drawText("TrustForge Security Report", {
      x: 50,
      y: height - 50,
      size: 24,
      font: boldFont,
    });

    yPos = height - 100;
    const metadata = [
      ["File Name:", data.fileName],
      ["Scan ID:", data.scanId],
      ["Scan Date:", new Date().toISOString().split("T")[0]],
      ["MD5 Hash:", data.reportData.md5 || "N/A"],
      ["SHA1 Hash:", data.reportData.sha1 || "N/A"],
      ["Size:", data.reportData.size || "N/A"],
    ];

    metadata.forEach(([label, value]) => {
      page.drawText(label, { x: 50, y: yPos, size: 12, font: boldFont });
      page.drawText(value as string, { x: 150, y: yPos, size: 12, font });
      yPos -= 20;
    });

    yPos -= 20;
    page.drawText("TrustForge Security Score", {
      x: 50,
      y: yPos,
      size: 14,
      font: boldFont,
    });

    let scoreColor: RGB;
    if (data.tfScore >= 80) {
      scoreColor = rgb(0, 0.7, 0);
    } else if (data.tfScore >= 60) {
      scoreColor = rgb(1, 0.5, 0);
    } else {
      scoreColor = rgb(1, 0, 0);
    }

    page.drawText(`${data.tfScore}`, {
      x: 250,
      y: yPos,
      size: 20,
      font: boldFont,
      color: scoreColor,
    });

    yPos -= 40;
    page.drawText("Security Findings", {
      x: 50,
      y: yPos,
      size: 16,
      font: boldFont,
    });
    yPos -= 25;

    const pageMargin = 50;
    const maxWidth = width - pageMargin * 2;
    const lineHeight = 15;
    const paragraphSpacing = 10;
    const sectionSpacing = 25;

    const drawSectionHeader = (title: string) => {
      if (yPos < 100) {
        const newPage = createNewPage();
        page = newPage.page;
        yPos = newPage.yPos;
      }

      page.drawText(title, {
        x: 50,
        y: yPos,
        size: 14,
        font: boldFont,
      });
      yPos -= 20;
    };

    const drawText = (
      text: string,
      options: {
        x: number;
        y: number;
        size: number;
        font: any;
        color?: RGB;
      }
    ) => {
      const sanitizedText = text
        .replace(/[\u0000-\u001F\u007F-\u009F]/g, "")
        .replace(/[\u2028\u2029]/g, " ")
        .replace(/\n/g, " ")
        .replace(/\r/g, "")
        .replace(/\t/g, "    ")
        .trim();

      if (!sanitizedText) {
        return options.y - lineHeight;
      }

      const words = sanitizedText.split(" ");
      let line = "";
      const fontSize = options.size;
      let currentY = options.y;

      for (const word of words) {
        const testLine = line + word + " ";
        const testWidth = options.font.widthOfTextAtSize(testLine, fontSize);

        if (testWidth > maxWidth) {
          if (currentY < 100) {
            const newPage = createNewPage();
            page = newPage.page;
            currentY = newPage.yPos;
          }

          try {
            page.drawText(line, {
              x: options.x,
              y: currentY,
              size: fontSize,
              font: options.font,
              color: options.color,
            });
          } catch (error) {
            this.logger.warn(
              `Error drawing text: ${error.message}. Skipping line.`
            );
          }

          currentY -= lineHeight;
          line = word + " ";
        } else {
          line = testLine;
        }
      }

      if (line.trim()) {
        if (currentY < 100) {
          const newPage = createNewPage();
          page = newPage.page;
          currentY = newPage.yPos;
        }

        try {
          page.drawText(line.trim(), {
            x: options.x,
            y: currentY,
            size: fontSize,
            font: options.font,
            color: options.color,
          });
        } catch (error) {
          this.logger.warn(
            `Error drawing text: ${error.message}. Skipping line.`
          );
        }

        currentY -= lineHeight;
      }

      return currentY;
    };

    const drawJsonContent = (
      content: any,
      options: {
        x: number;
        y: number;
        size: number;
        font: any;
      }
    ) => {
      try {
        let stringified: string;
        if (typeof content === "string") {
          stringified = content;
        } else {
          const formatObject = (obj: any, level = 0): string => {
            if (level > 2) {
              return typeof obj === "object" ? "[Complex Object]" : String(obj);
            }

            if (Array.isArray(obj)) {
              if (obj.length === 0) return "[]";
              return obj
                .map((item) => formatObject(item, level + 1))
                .join(", ");
            }

            if (obj !== null && typeof obj === "object") {
              const entries = Object.entries(obj);
              if (entries.length === 0) return "{}";
              return entries
                .map(([key, val]) => `${key}: ${formatObject(val, level + 1)}`)
                .join("; ");
            }

            return String(obj);
          };

          stringified = formatObject(content);

          if (stringified.length > 200) {
            stringified = stringified.substring(0, 197) + "...";
          }
        }

        return drawText(stringified, {
          x: options.x,
          y: options.y,
          size: options.size,
          font: options.font,
        });
      } catch (error) {
        this.logger.warn(`Error processing JSON content: ${error.message}`);
        return options.y - lineHeight;
      }
    };

    if (
      data.reportData.appsec?.high &&
      data.reportData.appsec.high.length > 0
    ) {
      drawSectionHeader("HIGH SEVERITY FINDINGS");

      data.reportData.appsec.high.forEach((finding: any, index: number) => {
        if (yPos < 100) {
          const newPage = createNewPage();
          page = newPage.page;
          yPos = newPage.yPos;
        }

        page.drawText(`${index + 1}. ${finding.title || "Untitled Finding"}`, {
          x: 50,
          y: yPos,
          size: 12,
          font: boldFont,
          color: rgb(0.8, 0, 0),
        });
        yPos -= lineHeight + 5;

        if (finding.description) {
          yPos = drawText(finding.description, {
            x: 70,
            y: yPos,
            size: 10,
            font,
          });
        }

        if (finding.recommendation) {
          yPos -= paragraphSpacing;
          page.drawText("Recommendation:", {
            x: 70,
            y: yPos,
            size: 10,
            font: boldFont,
          });
          yPos -= lineHeight;

          yPos = drawText(finding.recommendation, {
            x: 90,
            y: yPos,
            size: 10,
            font,
          });
        }

        yPos -= sectionSpacing;
      });
    }

    if (
      data.reportData.appsec?.medium &&
      data.reportData.appsec.medium.length > 0
    ) {
      drawSectionHeader("MEDIUM SEVERITY FINDINGS");

      data.reportData.appsec.medium.forEach((finding: any, index: number) => {
        if (yPos < 100) {
          const newPage = createNewPage();
          page = newPage.page;
          yPos = newPage.yPos;
        }

        page.drawText(`${index + 1}. ${finding.title || "Untitled Finding"}`, {
          x: 50,
          y: yPos,
          size: 12,
          font: boldFont,
          color: rgb(0.9, 0.6, 0),
        });
        yPos -= lineHeight + 5;

        if (finding.description) {
          yPos = drawText(finding.description, {
            x: 70,
            y: yPos,
            size: 10,
            font,
          });
        }

        if (finding.recommendation) {
          yPos -= paragraphSpacing;
          page.drawText("Recommendation:", {
            x: 70,
            y: yPos,
            size: 10,
            font: boldFont,
          });
          yPos -= lineHeight;

          yPos = drawText(finding.recommendation, {
            x: 90,
            y: yPos,
            size: 10,
            font,
          });
        }

        yPos -= sectionSpacing;
      });
    }

    if (data.reportData.appsec?.low && data.reportData.appsec.low.length > 0) {
      drawSectionHeader("LOW SEVERITY FINDINGS");

      data.reportData.appsec.low.forEach((finding: any, index: number) => {
        if (yPos < 100) {
          const newPage = createNewPage();
          page = newPage.page;
          yPos = newPage.yPos;
        }

        page.drawText(`${index + 1}. ${finding.title || "Untitled Finding"}`, {
          x: 50,
          y: yPos,
          size: 12,
          font: boldFont,
          color: rgb(0.4, 0.4, 0.4),
        });
        yPos -= lineHeight + 5;

        if (finding.description) {
          yPos = drawText(finding.description, {
            x: 70,
            y: yPos,
            size: 10,
            font,
          });
        }

        yPos -= sectionSpacing;
      });
    }

    if (
      data.reportData.appsec?.info &&
      data.reportData.appsec.info.length > 0
    ) {
      drawSectionHeader("INFORMATIONAL FINDINGS");

      data.reportData.appsec.info.forEach((finding: any, index: number) => {
        if (yPos < 100) {
          const newPage = createNewPage();
          page = newPage.page;
          yPos = newPage.yPos;
        }

        page.drawText(`${index + 1}. ${finding.title || "Untitled Finding"}`, {
          x: 50,
          y: yPos,
          size: 12,
          font: boldFont,
          color: rgb(0, 0.4, 0.8),
        });
        yPos -= lineHeight + 5;

        if (finding.description) {
          yPos = drawText(finding.description, {
            x: 70,
            y: yPos,
            size: 10,
            font,
          });
        }

        yPos -= sectionSpacing;
      });
    }

    if (
      data.reportData.permissions &&
      Object.keys(data.reportData.permissions).length > 0
    ) {
      const newPage = createNewPage();
      page = newPage.page;
      yPos = newPage.yPos;

      page.drawText("App Permissions", {
        x: 50,
        y: yPos,
        size: 16,
        font: boldFont,
      });
      yPos -= 30;

      const permissions = data.reportData.permissions;
      Object.keys(permissions).forEach((permissionKey) => {
        if (yPos < 100) {
          const newPage = createNewPage();
          page = newPage.page;
          yPos = newPage.yPos;
        }

        page.drawText(permissionKey, {
          x: 50,
          y: yPos,
          size: 11,
          font: boldFont,
        });
        yPos -= lineHeight;

        yPos = drawJsonContent(permissions[permissionKey], {
          x: 70,
          y: yPos,
          size: 10,
          font,
        });

        yPos -= sectionSpacing;
      });
    }

    if (data.findings.virustotal) {
      drawSectionHeader("VirusTotal Scan Results");

      if (data.findings.virustotal.error) {
        page.drawText("VirusTotal Error:", {
          x: 50,
          y: yPos,
          size: 12,
          font: boldFont,
          color: rgb(0.8, 0, 0),
        });
        yPos -= lineHeight;

        yPos = drawText(data.findings.virustotal.error, {
          x: 70,
          y: yPos,
          size: 10,
          font,
        });
        yPos -= sectionSpacing;
      } else {
        Object.entries(data.findings.virustotal).forEach(
          ([engine, result]: any) => {
            if (yPos < 100) {
              const newPage = createNewPage();
              page = newPage.page;
              yPos = newPage.yPos;
            }

            page.drawText(`${engine}: ${result.category}`, {
              x: 50,
              y: yPos,
              size: 10,
              font,
            });
            yPos -= lineHeight;
          }
        );
        yPos -= sectionSpacing;
      }
    }

    if (data.findings.recommendations?.length) {
      drawSectionHeader("Recommendations");
      data.findings.recommendations.forEach(
        (recommendation: string, index: number) => {
          yPos = drawText(`${index + 1}. ${recommendation}`, {
            x: 50,
            y: yPos,
            size: 12,
            font,
          });
          yPos -= sectionSpacing;
        }
      );
    }

    const finalPage = createNewPage();
    page = finalPage.page;
    yPos = finalPage.yPos;

    page.drawText("Security Summary", {
      x: 50,
      y: yPos,
      size: 16,
      font: boldFont,
    });
    yPos -= 30;

    const highCount = data.reportData.appsec?.high?.length || 0;
    const mediumCount = data.reportData.appsec?.medium?.length || 0;
    const lowCount = data.reportData.appsec?.low?.length || 0;
    const infoCount = data.reportData.appsec?.info?.length || 0;

    page.drawText(`High Severity Issues: ${highCount}`, {
      x: 70,
      y: yPos,
      size: 12,
      font: boldFont,
      color: rgb(0.8, 0, 0),
    });
    yPos -= lineHeight + 5;

    page.drawText(`Medium Severity Issues: ${mediumCount}`, {
      x: 70,
      y: yPos,
      size: 12,
      font: boldFont,
      color: rgb(0.9, 0.6, 0),
    });
    yPos -= lineHeight + 5;

    page.drawText(`Low Severity Issues: ${lowCount}`, {
      x: 70,
      y: yPos,
      size: 12,
      font: boldFont,
      color: rgb(0.4, 0.4, 0.4),
    });
    yPos -= lineHeight + 5;

    page.drawText(`Informational Issues: ${infoCount}`, {
      x: 70,
      y: yPos,
      size: 12,
      font: boldFont,
      color: rgb(0, 0.4, 0.8),
    });
    yPos -= sectionSpacing;

    yPos -= 40;
    page.drawText(`Report generated by TrustForge Security Scanner`, {
      x: 50,
      y: yPos,
      size: 10,
      font: font,
    });
    yPos -= lineHeight;
    page.drawText(`Generated on: ${new Date().toLocaleString()}`, {
      x: 50,
      y: yPos,
      size: 10,
      font: font,
    });

    const pdfBytes = await pdfDoc.save();
    return Buffer.from(pdfBytes);
  }

  private async runMobSFScan(filePath: string): Promise<any> {
    this.logger.log(`Starting MobSF scan for file: ${filePath}`);
    const form = new FormData();
    form.append("file", fs.createReadStream(filePath));

    try {
      // Step 1: Upload the file
      const uploadResponse = await axios.post(
        `${this.mobSFUrl}/api/v1/upload`,
        form,
        {
          headers: {
            ...form.getHeaders(),
            "X-Mobsf-Api-Key": this.mobSFApiKey,
          },
        }
      );

      const fileHash = uploadResponse.data.hash;
      this.logger.log(`File uploaded successfully. Hash: ${fileHash}`);

      // Step 2: Start the scan
      const scanResponse = await axios.post(
        `${this.mobSFUrl}/api/v1/scan`,
        qs.stringify({ hash: fileHash }),
        {
          headers: {
            "X-Mobsf-Api-Key": this.mobSFApiKey,
            "Content-Type": "application/x-www-form-urlencoded",
          },
        }
      );

      this.logger.log("Scan started successfully");

      // Step 3: Poll scan logs for completion
      const scanResult = await this.pollMobSFScanLogs(fileHash);
      this.logger.log("MobSF scan completed successfully");

      // Step 4: Get the report
      const reportResponse = await axios.post(
        `${this.mobSFUrl}/api/v1/report_json`,
        qs.stringify({ hash: fileHash }),
        {
          headers: {
            "X-Mobsf-Api-Key": this.mobSFApiKey,
            "Content-Type": "application/x-www-form-urlencoded",
          },
        }
      );

      return reportResponse.data;
    } catch (error) {
      this.logger.error(`MobSF scan failed: ${error.message}`);
      throw new Error(`MobSF scan failed: ${error.message}`);
    }
  }

  private async pollMobSFScanLogs(fileHash: string): Promise<any> {
    const maxAttempts = 60; // Max 60 attempts (30 minutes if polling every 30 seconds)
    const pollInterval = 30000; // Poll every 30 seconds
    let attempts = 0;
    let lastLogTimestamp = "";

    while (attempts < maxAttempts) {
      attempts++;
      this.logger.log(
        `Checking MobSF scan logs (attempt ${attempts}/${maxAttempts})`
      );

      try {
        const logsResponse = await axios.post(
          `${this.mobSFUrl}/api/v1/scan_logs`,
          qs.stringify({ hash: fileHash }),
          {
            headers: {
              "X-Mobsf-Api-Key": this.mobSFApiKey,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout: 60000, // Set timeout to 60 seconds
          }
        );

        if (!logsResponse.data || !Array.isArray(logsResponse.data.logs)) {
          throw new Error("Invalid logs response format");
        }

        const logs = logsResponse.data.logs;
        if (logs.length === 0) {
          this.logger.log("No logs available yet");
          await new Promise((resolve) => setTimeout(resolve, pollInterval));
          continue;
        }

        // Get the most recent log entry
        const lastLog = logs[logs.length - 1];
        const currentLogTimestamp =
          typeof lastLog === "string"
            ? lastLog.split(" - ")[0]
            : lastLog.timestamp;

        // Skip if we've already seen this log entry
        if (currentLogTimestamp === lastLogTimestamp) {
          await new Promise((resolve) => setTimeout(resolve, pollInterval));
          continue;
        }

        lastLogTimestamp = currentLogTimestamp;
        const lastLogStr =
          typeof lastLog === "string" ? lastLog : JSON.stringify(lastLog);
        this.logger.log(`MobSF scan log: ${lastLogStr}`);

        // Check for completion indicators
        const lastLogLower = lastLogStr.toLowerCase();
        if (
          lastLogLower.includes("scan completed") ||
          lastLogLower.includes("scan finished") ||
          lastLogLower.includes("scan done") ||
          lastLogLower.includes("saving to database") ||
          lastLogLower.includes("static analyzer completed")
        ) {
          return logsResponse.data;
        }

        // Check for failure indicators
        if (
          lastLogLower.includes("scan failed") ||
          lastLogLower.includes("error")
        ) {
          throw new Error(`Scan failed: ${lastLogStr}`);
        }

        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      } catch (error) {
        if (attempts >= maxAttempts) {
          throw new Error(
            `MobSF scan timed out after ${maxAttempts} attempts: ${error.message}`
          );
        }
        this.logger.warn(
          `MobSF logs check attempt ${attempts} failed: ${error.message}`
        );
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      }
    }

    throw new Error(`MobSF scan timed out after ${maxAttempts} attempts`);
  }

  private async runVirusTotalScan(filePath: string): Promise<any> {
    this.logger.log(`Starting VirusTotal scan for file: ${filePath}`);

    try {
      const stats = await fsPromises.stat(filePath);
      const fileSize = stats.size;
      const fileSizeInMB = fileSize / (1024 * 1024);

      // VirusTotal's limit is 650MB
      if (fileSizeInMB > 650) {
        this.logger.warn(
          `File too large for VirusTotal scan (${fileSizeInMB.toFixed(2)}MB > 650MB limit)`
        );
        return {
          skipped: true,
          reason: `File too large for VirusTotal scan (${fileSizeInMB.toFixed(2)}MB > 650MB limit)`,
        };
      }

      // Step 1: Get upload URL
      const uploadUrlResponse = await axios.get(
        "https://www.virustotal.com/api/v3/files/upload_url",
        {
          headers: {
            "x-apikey": this.virusTotalApiKey,
          },
        }
      );

      const uploadUrl = uploadUrlResponse.data.data;
      this.logger.log(`Obtained VirusTotal upload URL: ${uploadUrl}`);

      // Step 2: Upload file using the provided URL
      const fileStream = fs.createReadStream(filePath);
      const form = new FormData();
      form.append("file", fileStream);

      const uploadResponse = await axios.post(uploadUrl, form, {
        headers: {
          ...form.getHeaders(),
          "x-apikey": this.virusTotalApiKey,
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
      });

      if (uploadResponse.status !== 200) {
        throw new Error(
          `VirusTotal upload failed with status ${uploadResponse.status}`
        );
      }

      const analysisId = uploadResponse.data.data.id;
      this.logger.log(`VirusTotal analysis ID: ${analysisId}`);

      return await this.pollVirusTotalResults(analysisId);
    } catch (error) {
      this.logger.error(`VirusTotal scan failed: ${error.message}`);

      // If the upload URL method fails, fall back to hash lookup for large files
      if (error.response?.status === 413 || error.message.includes("large")) {
        try {
          this.logger.log("Attempting hash lookup as fallback");
          const fileBuffer = await fsPromises.readFile(filePath);
          const hash = createHash("sha256").update(fileBuffer).digest("hex");

          const response = await axios.get(
            `https://www.virustotal.com/api/v3/files/${hash}`,
            {
              headers: {
                "x-apikey": this.virusTotalApiKey,
              },
            }
          );

          if (response.status === 200) {
            return response.data.data.attributes.last_analysis_results;
          }
        } catch (fallbackError) {
          this.logger.error(
            `VirusTotal hash lookup also failed: ${fallbackError.message}`
          );
        }
      }

      return {
        error: error.message,
        skipped: true,
        reason: "VirusTotal scan failed",
      };
    }
  }

  private async pollVirusTotalResults(analysisId: string): Promise<any> {
    const url = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
    let attempts = 0;
    const maxAttempts = 30;
    const pollInterval = 15000;

    while (attempts < maxAttempts) {
      try {
        attempts++;
        this.logger.log(
          `Checking VirusTotal results (attempt ${attempts}/${maxAttempts})...`
        );

        const response = await axios.get(url, {
          headers: {
            "x-apikey": this.virusTotalApiKey,
          },
        });

        const status = response.data.data.attributes.status;
        this.logger.log(`VirusTotal scan status: ${status}`);

        if (status === "completed") {
          return response.data.data.attributes.results;
        }

        if (status === "queued" || status === "in-progress") {
          await new Promise((resolve) => setTimeout(resolve, pollInterval));
          continue;
        }

        if (status === "failed") {
          throw new Error("VirusTotal analysis failed");
        }
      } catch (error) {
        if (attempts >= maxAttempts) {
          throw new Error(
            `VirusTotal scan timed out after ${maxAttempts} attempts: ${error.message}`
          );
        }
        this.logger.warn(
          `VirusTotal poll attempt ${attempts} failed: ${error.message}`
        );
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      }
    }

    throw new Error(`VirusTotal scan timed out after ${maxAttempts} attempts`);
  }

  private async runMetaDefenderScan(filePath: string): Promise<any> {
    this.logger.log(`Starting MetaDefender scan for file: ${filePath}`);
    const fileBuffer = await fsPromises.readFile(filePath);

    try {
      const fileType = await fileTypeFromBuffer(
        await fsPromises.readFile(filePath)
      );
      if (
        !fileType ||
        ![
          "application/vnd.android.package-archive",
          "application/octet-stream",
        ].includes(fileType.mime)
      ) {
        throw new Error(
          `Invalid file type: ${fileType?.mime}. Only APK or IPA files are allowed.`
        );
      }

      // Upload file to MetaDefender
      const fileStream = fs.createReadStream(filePath);
      const uploadResponse = await axios.post(
        this.metaDefenderUrl,
        fileStream,
        {
          headers: {
            apikey: this.metaDefenderApiKey,
            "Content-Type": "application/octet-stream",
          },
          maxContentLength: Infinity,
          maxBodyLength: Infinity,
        }
      );

      if (uploadResponse.status !== 200) {
        throw new Error(
          `MetaDefender upload failed with status ${uploadResponse.status}`
        );
      }

      const dataId = uploadResponse.data.data_id;
      this.logger.log(`MetaDefender data ID: ${dataId}`);

      return await this.pollMetaDefenderResults(dataId);
    } catch (error) {
      this.logger.error(`MetaDefender scan failed: ${error.message}`);
      throw error;
    }
  }

  private async pollMetaDefenderResults(dataId: string): Promise<any> {
    const url = `https://api.metadefender.com/v4/file/${dataId}`;
    let attempts = 0;
    const maxAttempts = 30;
    const pollInterval = 15000;

    while (attempts < maxAttempts) {
      try {
        attempts++;
        this.logger.log(
          `Checking MetaDefender results (attempt ${attempts}/${maxAttempts})...`
        );

        const response = await axios.get(url, {
          headers: {
            apikey: this.metaDefenderApiKey,
          },
        });

        const status = response.data.scan_results.progress_percentage;
        this.logger.log(`MetaDefender scan progress: ${status}%`);

        if (status === 100) {
          return response.data.scan_results;
        }

        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      } catch (error) {
        if (attempts >= maxAttempts) {
          throw new Error(
            `MetaDefender scan timed out after ${maxAttempts} attempts: ${error.message}`
          );
        }
        this.logger.warn(
          `MetaDefender poll attempt ${attempts} failed: ${error.message}`
        );
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      }
    }

    throw new Error(
      `MetaDefender scan timed out after ${maxAttempts} attempts`
    );
  }

  private async runHybridAnalysisScan(filePath: string): Promise<any> {
    this.logger.log(`Starting Hybrid Analysis scan for file: ${filePath}`);

    try {
      // Validate file type (APK only)
      const fileType = await fileTypeFromBuffer(
        await fsPromises.readFile(filePath)
      );
      if (
        !fileType ||
        fileType.mime !== "application/vnd.android.package-archive"
      ) {
        throw new Error(
          `Invalid file type: ${fileType?.mime}. Only APK files are allowed.`
        );
      }

      const fileStream = fs.createReadStream(filePath);
      const form = new FormData();
      form.append("file", fileStream);
      form.append("environment_id", "200"); // Android Static Analysis
      form.append("no_share_third_party", "1"); // Optional (as string)
      form.append("allow_community_access", "true"); // Must be "true" (string) or true (boolean)

      // Upload file to Hybrid Analysis
      const uploadResponse = await axios.post(
        `${this.hybridAnalysisUrl}/submit/file`,
        form,
        {
          headers: {
            ...form.getHeaders(),
            "api-key": this.hybridAnalysisApiKey,
          },
          maxContentLength: Infinity,
          maxBodyLength: Infinity,
        }
      );

      if (uploadResponse.status !== 201) {
        // Successful submission returns 201
        this.logger.error(
          `Hybrid Analysis upload failed: ${JSON.stringify(uploadResponse.data)}`
        );
        throw new Error(
          `Hybrid Analysis upload failed with status ${uploadResponse.status}`
        );
      }

      const jobId = uploadResponse.data.job_id;
      this.logger.log(`Hybrid Analysis job ID: ${jobId}`);

      return await this.pollHybridAnalysisResults(jobId);
    } catch (error: any) {
      if (error.response) {
        this.logger.error(
          `Hybrid Analysis API error: ${JSON.stringify(error.response.data)}`
        );
      }
      this.logger.error(`Hybrid Analysis scan failed: ${error.message}`);
      throw error;
    }
  }

  private async pollHybridAnalysisResults(jobId: string): Promise<any> {
    const url = `${this.hybridAnalysisUrl}/report/${jobId}/state`;
    const reportUrl = `${this.hybridAnalysisUrl}/report/${jobId}/summary`;
    let attempts = 0;
    const maxAttempts = 30;
    const pollInterval = 10000;

    while (attempts < maxAttempts) {
      try {
        attempts++;
        this.logger.log(
          `Checking Hybrid Analysis results (attempt ${attempts}/${maxAttempts})...`
        );

        // First check the state
        const stateResponse = await axios.get(url, {
          headers: {
            "api-key": this.hybridAnalysisApiKey,
            accept: "application/json",
          },
        });

        this.logger.log(
          `Hybrid Analysis scan state: ${stateResponse.data.state}`
        );

        if (stateResponse.data.state === "SUCCESS") {
          // If completed, get the full report
          const reportResponse = await axios.get(reportUrl, {
            headers: {
              "api-key": this.hybridAnalysisApiKey,
              accept: "application/json",
            },
          });
          return reportResponse.data;
        }

        if (stateResponse.data.state === "IN_PROGRESS") {
          await new Promise((resolve) => setTimeout(resolve, pollInterval));
          continue;
        }

        if (stateResponse.data.state === "ERROR") {
          throw new Error("Hybrid Analysis scan failed");
        }
      } catch (error) {
        if (attempts >= maxAttempts) {
          throw new Error(
            `Hybrid Analysis scan timed out after ${maxAttempts} attempts: ${error.message}`
          );
        }

        if (error.response?.status === 404) {
          // Job might not be ready yet
          await new Promise((resolve) => setTimeout(resolve, pollInterval));
          continue;
        }

        this.logger.warn(
          `Hybrid Analysis poll attempt ${attempts} failed: ${error.message}`
        );
        await new Promise((resolve) => setTimeout(resolve, pollInterval));
      }
    }

    throw new Error(
      `Hybrid Analysis scan timed out after ${maxAttempts} attempts`
    );
  }

  private calculateTFScore(results: {
    mobsf?: any;
    virustotal?: any;
    metadefender?: any;
    hybridAnalysis?: any;
  }): number {
    let score = 100;

    // MobSF Scoring
    if (results.mobsf?.appsec) {
      const { high = [], medium = [], low = [] } = results.mobsf.appsec;
      score -= high.length * 10; // Deduct 10 points per high-severity issue
      score -= medium.length * 5; // Deduct 5 points per medium-severity issue
      score -= low.length * 2; // Deduct 2 points per low-severity issue
    }

    // VirusTotal Scoring
    if (results.virustotal && !results.virustotal.error) {
      const maliciousCount = Object.values(results.virustotal).filter(
        (result: any) => result.category === "malicious"
      ).length;
      score -= maliciousCount * 5; // Deduct 5 points per malicious detection
    }

    // MetaDefender Scoring
    if (results.metadefender && !results.metadefender.error) {
      const maliciousCount = results.metadefender.scan_details
        ? Object.values(results.metadefender.scan_details).filter(
            (detail: any) => detail.threat_found
          ).length
        : 0;
      score -= maliciousCount * 5; // Deduct 5 points per malicious detection
    }

    // Hybrid Analysis Scoring
    if (results.hybridAnalysis && !results.hybridAnalysis.error) {
      const { verdict, threats = [] } = results.hybridAnalysis;
      if (verdict === "malicious") {
        score -= 20; // Deduct 20 points for a malicious verdict
      } else if (verdict === "suspicious") {
        score -= 10; // Deduct 10 points for a suspicious verdict
      }
      score -= threats.length * 3; // Deduct 3 points per identified threat
    }

    // Ensure the score is within bounds
    return Math.max(0, Math.min(100, score));
  }

  private generateRecommendations(scanResults: any): any {
    const recommendations = [];

    // Example: MobSF findings
    if (scanResults.mobsf?.appsec?.high?.length) {
      recommendations.push("Fix high-severity vulnerabilities immediately.");
    }
    if (scanResults.mobsf?.appsec?.medium?.length) {
      recommendations.push(
        "Review and address medium-severity vulnerabilities."
      );
    }
    if (scanResults.mobsf?.appsec?.low?.length) {
      recommendations.push(
        "Follow best practices to address low-severity issues."
      );
    }

    // Example: VirusTotal findings
    if (scanResults.virustotal) {
      const maliciousCount = Object.values(scanResults.virustotal).filter(
        (result: any) => result.category === "malicious"
      ).length;
      if (maliciousCount > 0) {
        recommendations.push(
          "Investigate files flagged as malicious by VirusTotal."
        );
      }
    }

    // Example: MetaDefender findings
    if (scanResults.metadefender?.scan_details) {
      const threats = Object.values(
        scanResults.metadefender.scan_details
      ).filter((detail: any) => detail.threat_found);
      if (threats.length > 0) {
        recommendations.push("Review threats identified by MetaDefender.");
      }
    }

    // Example: Hybrid Analysis findings
    if (scanResults.hybridAnalysis?.verdict === "malicious") {
      recommendations.push(
        "Take immediate action on malicious findings from Hybrid Analysis."
      );
    }

    return recommendations;
  }
}
