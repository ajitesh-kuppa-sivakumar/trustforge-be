import {
  Injectable,
  BadRequestException,
  NotFoundException,
  InternalServerErrorException,
} from "@nestjs/common";
import { InjectQueue } from "@nestjs/bull";
import { Queue } from "bull";
import { SupabaseService } from "../supabase/supabase.service";
import { extname, basename } from "path";
import { Logger } from "@nestjs/common";
import { v4 as uuidv4 } from "uuid";

@Injectable()
export class ScanService {
  private readonly logger = new Logger(ScanService.name);

  constructor(
    private readonly supabaseService: SupabaseService,
    @InjectQueue("scan") private readonly scanQueue: Queue
  ) {}

  async uploadAndScan(file: Express.Multer.File, userId: any) {
    this.logger.debug("Starting uploadAndScan method");
    this.logger.debug(`File name: ${file.originalname}`);
    this.logger.debug(`User ID (raw): ${userId}`);

    // Validate file extension
    const ext = extname(file.originalname).toLowerCase();
    if (ext !== ".apk" && ext !== ".ipa") {
      this.logger.error("Invalid file type");
      throw new BadRequestException("Only .apk and .ipa files are allowed");
    }

    try {
      // Ensure the bucket exists
      // this.logger.debug("Ensuring the bucket exists");
      // await this.supabaseService.ensureBucketExists("app-uploads");

      // Sanitize userId and file name
      const sanitizedUserId = String(userId).trim();
      const sanitizedFileName = `${uuidv4()}_${basename(file.originalname).replace(/[^a-zA-Z0-9.]/g, "_")}`;
      const filePath = `${sanitizedUserId}/${sanitizedFileName}`;
      this.logger.debug(`Sanitized file path: ${filePath}`);

      // Validate filePath before uploading
      if (!filePath || typeof filePath !== "string") {
        this.logger.error(`Invalid file path: ${filePath}`);
        throw new InternalServerErrorException(
          "Generated file path is invalid"
        );
      }

      // Debug userId and filePath values
      this.logger.debug(`User ID (stringified): ${sanitizedUserId}`);
      this.logger.debug(`Final file path: ${filePath}`);

      // Upload file to Supabase Storage
      this.logger.debug("Uploading file to Supabase Storage");
      const uploadResult = await this.supabaseService
        .getAdminClient()
        .storage.from("app-uploads")
        .upload(filePath, file.buffer, { contentType: file.mimetype });

      if (uploadResult.error) {
        this.logger.error(`File upload failed: ${uploadResult.error.message}`);
        throw new InternalServerErrorException("File upload failed");
      }

      this.logger.debug("File uploaded successfully");

      // Use correct file URL
      const fileUrl = `app-uploads/${filePath}`;
      this.logger.debug(`File URL: ${fileUrl}`);

      // Create scan record in database
      this.logger.debug("Creating scan record in database");
      const { data: scanData, error: scanError } = await this.supabaseService
        .getAdminClient()
        .from("scans")
        .insert({
          user_id: sanitizedUserId,
          file_name: file.originalname,
          file_url: fileUrl,
          scan_status: "pending",
        })
        .select()
        .single();

      if (scanError) {
        this.logger.error(`Failed to create scan record: ${scanError.message}`);
        throw new InternalServerErrorException("Failed to create scan record");
      }

      this.logger.debug("Scan record created successfully");

      // Add scan job to queue
      this.logger.debug("Adding scan job to queue");
      await this.scanQueue.add("process", {
        scanId: scanData.scan_id,
        userId: sanitizedUserId,
        filePath: fileUrl,
      });

      this.logger.debug("Scan job added to queue successfully");

      return {
        message: "File uploaded and scan initiated",
        scanId: scanData.scan_id,
      };
    } catch (error) {
      this.logger.error(`Scan initiation failed: ${error.message}`);
      throw new InternalServerErrorException("Scan initiation failed");
    }
  }

  async getScanStatus(scanId: string, userId: string) {
    const { data, error } = await this.supabaseService
      .getAdminClient()
      .from("scans")
      .select("scan_status")
      .eq("scan_id", scanId)
      .eq("user_id", userId)
      .single();

    if (error || !data) {
      throw new NotFoundException("Scan not found");
    }

    return {
      status: data.scan_status,
    };
  }

  async retryScan(scanId: string, userId: string) {
    // Fetch the scan record
    const { data: scan, error } = await this.supabaseService
      .getAdminClient()
      .from("scans")
      .select("*")
      .eq("scan_id", scanId)
      .eq("user_id", userId)
      .single();

    if (error || !scan) {
      throw new NotFoundException("Scan not found");
    }

    // Ensure the scan is in a failed state
    if (scan.scan_status !== "failed") {
      throw new BadRequestException("Only failed scans can be retried");
    }

    // Add the scan job back to the queue
    await this.scanQueue.add("process", {
      scanId: scan.scan_id,
      userId: scan.user_id,
      filePath: scan.file_url,
    });

    // Update the scan status to "retrying"
    const { error: updateError } = await this.supabaseService
      .getAdminClient()
      .from("scans")
      .update({ scan_status: "retrying" })
      .eq("scan_id", scanId);

    if (updateError) {
      throw new InternalServerErrorException("Failed to update scan status");
    }

    return { message: "Scan retry initiated successfully", scanId };
  }
}
