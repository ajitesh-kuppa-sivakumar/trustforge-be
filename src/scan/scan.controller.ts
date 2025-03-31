import {
  Controller,
  Post,
  Get,
  Param,
  UseGuards,
  UseInterceptors,
  UploadedFile,
  ParseUUIDPipe,
  Logger,
  BadRequestException,
} from "@nestjs/common";
import { FileInterceptor } from "@nestjs/platform-express";
import { Options as MulterOptions } from "multer";
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiConsumes,
  ApiBody,
} from "@nestjs/swagger";
import { Express } from "express";
import { SupabaseAuthGuard } from "../common/guards/supabase-auth.guard";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { ScanService } from "./scan.service";
import { FileUploadDto } from "./dto/file-upload.dto";

const multerOptions: MulterOptions = {
  limits: {
    fileSize: 100 * 1024 * 1024,
  },
};

@ApiTags("Scan")
@Controller("scan")
@UseGuards(SupabaseAuthGuard)
@ApiBearerAuth()
@UseInterceptors(FileInterceptor("file", multerOptions))
export class ScanController {
  private readonly logger = new Logger(ScanService.name);
  constructor(private readonly scanService: ScanService) {}

  @Post("upload")
  @ApiOperation({ summary: "Upload app for scanning" })
  @ApiConsumes("multipart/form-data")
  @ApiBody({ type: FileUploadDto })
  @ApiResponse({ status: 201, description: "File uploaded and scan initiated" })
  @ApiResponse({ status: 400, description: "Invalid file type" })
  async uploadFile(
    @UploadedFile() file: Express.Multer.File,
    @CurrentUser() user: any
  ) {
    if (!file) {
      throw new BadRequestException("No file uploaded");
    }

    const userId = user.id; // Extract userId from the user object
    this.logger.debug(userId);
    return this.scanService.uploadAndScan(file, userId);
  }

  @Get("status/:scanId")
  @ApiOperation({ summary: "Get scan status" })
  @ApiResponse({ status: 200, description: "Scan status retrieved" })
  @ApiResponse({ status: 404, description: "Scan not found" })
  async getScanStatus(
    @Param("scanId", ParseUUIDPipe) scanId: string,
    @CurrentUser() user: any
  ) {
    const userId = user.id; // Extract userId from the user object
    return this.scanService.getScanStatus(scanId, userId);
  }

  @Post("retry/:scanId")
  @ApiOperation({ summary: "Retry a failed scan" })
  @ApiResponse({
    status: 200,
    description: "Scan retry initiated successfully",
  })
  @ApiResponse({ status: 404, description: "Scan not found" })
  @ApiResponse({ status: 400, description: "Scan cannot be retried" })
  async retryScan(
    @Param("scanId", ParseUUIDPipe) scanId: string,
    @CurrentUser() user: any
  ) {
    const userId = user.id; // Extract userId from the user object
    return this.scanService.retryScan(scanId, userId);
  }
}
