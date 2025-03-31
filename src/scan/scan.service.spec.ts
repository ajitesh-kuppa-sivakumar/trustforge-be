import { Test, TestingModule } from "@nestjs/testing";
import { getQueueToken } from "@nestjs/bull";
import { ScanService } from "./scan.service";
import { SupabaseService } from "../supabase/supabase.service";
import {
  BadRequestException,
  InternalServerErrorException,
  NotFoundException,
} from "@nestjs/common";
import { StorageError } from "@supabase/storage-js";

describe("ScanService", () => {
  let service: ScanService;
  let supabaseService: SupabaseService;
  let mockQueue: any;

  const mockSupabaseService = {
    getAdminClient: jest.fn(() => ({
      storage: {
        from: jest.fn().mockReturnValue({
          upload: jest.fn(),
          download: jest.fn(),
        }),
      },
      from: jest.fn().mockReturnValue({
        insert: jest.fn().mockReturnValue({
          select: jest.fn().mockReturnValue({
            single: jest.fn(),
          }),
        }),
        select: jest.fn().mockReturnValue({
          eq: jest.fn().mockReturnValue({
            eq: jest.fn().mockReturnValue({
              single: jest.fn(),
            }),
          }),
        }),
      }),
    })),
  };

  beforeEach(async () => {
    mockQueue = {
      add: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ScanService,
        {
          provide: SupabaseService,
          useValue: mockSupabaseService,
        },
        {
          provide: getQueueToken("scan"),
          useValue: mockQueue,
        },
      ],
    }).compile();

    service = module.get<ScanService>(ScanService);
    supabaseService = module.get<SupabaseService>(SupabaseService);
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  describe("uploadAndScan", () => {
    const mockFile = {
      originalname: "test.apk",
      buffer: Buffer.from("test"),
    } as Express.Multer.File;

    const userId = "test-user-id";

    it("should successfully upload and initiate scan", async () => {
      const mockUploadResponse = {
        id: "1",
        path: "test-path",
        fullPath: "app-uploads/test-path",
      };
      const mockScanData = { scan_id: "test-scan-id" };

      const supabaseClient = supabaseService.getAdminClient();
      jest
        .spyOn(supabaseClient.storage.from("app-uploads"), "upload")
        .mockResolvedValue({ data: mockUploadResponse, error: null });

      jest.spyOn(supabaseClient.from("scans"), "insert").mockReturnValue({
        select: jest.fn().mockReturnValue({
          single: jest
            .fn()
            .mockResolvedValue({ data: mockScanData, error: null }),
        }),
      } as any);

      const result = await service.uploadAndScan(mockFile, userId);

      expect(result).toEqual({
        message: "File uploaded and scan initiated",
        scanId: mockScanData.scan_id,
      });
      expect(mockQueue.add).toHaveBeenCalledWith("process", {
        scanId: mockScanData.scan_id,
        userId,
        filePath: expect.any(String),
      });
    });

    it("should throw BadRequestException for invalid file type", async () => {
      const invalidFile = {
        ...mockFile,
        originalname: "test.txt",
      } as Express.Multer.File;

      await expect(service.uploadAndScan(invalidFile, userId)).rejects.toThrow(
        BadRequestException
      );
    });

    it("should throw InternalServerErrorException on upload error", async () => {
      const supabaseClient = supabaseService.getAdminClient();
      jest
        .spyOn(supabaseClient.storage.from("app-uploads"), "upload")
        .mockResolvedValue({
          data: null,
          error: new StorageError("Upload failed"),
        });

      await expect(service.uploadAndScan(mockFile, userId)).rejects.toThrow(
        InternalServerErrorException
      );
    });
  });

  describe("getScanStatus", () => {
    const scanId = "test-scan-id";
    const userId = "test-user-id";

    it("should return scan status", async () => {
      const mockStatus = { scan_status: "completed" };
      const supabaseClient = supabaseService.getAdminClient();
      jest
        .spyOn(
          supabaseClient
            .from("scans")
            .select()
            .eq("scan_id", scanId)
            .eq("user_id", userId)
            .single(),
          "then"
        )
        .mockResolvedValue({ data: mockStatus, error: null });

      const result = await service.getScanStatus(scanId, userId);
      expect(result).toEqual({ status: mockStatus.scan_status });
    });
  });
});
