import { Test, TestingModule } from "@nestjs/testing";
import { Job } from "bull";
import { ScanProcessor } from "./scan.processor";
import { SupabaseService } from "../supabase/supabase.service";

describe("ScanProcessor", () => {
  let processor: ScanProcessor;
  let supabaseService: SupabaseService;

  const mockSupabaseService = {
    getAdminClient: jest.fn(() => ({
      storage: {
        from: jest.fn().mockReturnValue({
          download: jest.fn(),
          upload: jest.fn(),
        }),
      },
      from: jest.fn().mockReturnValue({
        update: jest.fn().mockReturnValue({
          eq: jest.fn(),
        }),
      }),
    })),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ScanProcessor,
        {
          provide: SupabaseService,
          useValue: mockSupabaseService,
        },
      ],
    }).compile();

    processor = module.get<ScanProcessor>(ScanProcessor);
    supabaseService = module.get<SupabaseService>(SupabaseService);
  });

  it("should be defined", () => {
    expect(processor).toBeDefined();
  });

  describe("processScan", () => {
    const mockJob = {
      data: {
        scanId: "test-scan-id",
        userId: "test-user-id",
        filePath: "test/path/file.apk",
      },
    } as Job<{ scanId: string; userId: string; filePath: string }>;

    it("should process scan successfully", async () => {
      const mockFileData = new Blob([Buffer.from("test")]);
      const supabaseClient = supabaseService.getAdminClient();

      jest
        .spyOn(supabaseClient.storage.from("app-uploads"), "download")
        .mockResolvedValue({ data: mockFileData, error: null });

      jest
        .spyOn(supabaseClient.storage.from("app-pdf-reports"), "upload")
        .mockResolvedValue({
          data: {
            id: "1",
            path: "test/path/report.pdf",
            fullPath: "full/test/path/report.pdf",
          },
          error: null,
        });

      jest
        .spyOn(supabaseClient.from("scans"), "update")
        .mockResolvedValue({ data: {}, error: null } as any);

      // Mock security scan functions
      jest
        .spyOn(processor as any, "runAndroBugsScan")
        .mockResolvedValue({ vulnerabilities: [] });
      jest
        .spyOn(processor as any, "runJadxDecompilation")
        .mockResolvedValue({ success: true });
      jest
        .spyOn(processor as any, "runApktoolDecompilation")
        .mockResolvedValue({ success: true });
      jest
        .spyOn(processor as any, "runMobSFScan")
        .mockResolvedValue({ findings: [] });

      await expect(processor.processScan(mockJob)).resolves.not.toThrow();

      expect(supabaseClient.from("scans").update).toHaveBeenCalledWith({
        scan_status: "completed",
        report_data: expect.any(Object),
        tf_score: expect.any(Number),
        pdf_report_url: expect.any(String),
      });
    });

    it("should handle scan failure", async () => {
      const supabaseClient = supabaseService.getAdminClient();

      jest
        .spyOn(supabaseClient.storage.from("app-uploads"), "download")
        .mockRejectedValue(new Error("Download failed"));

      await expect(processor.processScan(mockJob)).rejects.toThrow();

      expect(supabaseClient.from("scans").update).toHaveBeenCalledWith({
        scan_status: "failed",
      });
    });
  });

  describe("security scanning functions", () => {
    it("should run AndroBugs scan", async () => {
      const result = await (processor as any).runAndroBugsScan("test.apk");
      expect(result).toBeDefined();
    });

    it("should run Jadx decompilation", async () => {
      const result = await (processor as any).runJadxDecompilation(
        "test.apk",
        "output"
      );
      expect(result).toBeDefined();
    });

    it("should run Apktool decompilation", async () => {
      const result = await (processor as any).runApktoolDecompilation(
        "test.apk",
        "output"
      );
      expect(result).toBeDefined();
    });

    it("should run MobSF scan", async () => {
      const result = await (processor as any).runMobSFScan("test.apk");
      expect(result).toBeDefined();
    });
  });

  describe("report generation", () => {
    it("should calculate TF Score", () => {
      const score = (processor as any).calculateTFScore({}, {}, {}, {});
      expect(score).toBeDefined();
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
    });

    it("should generate PDF report", async () => {
      const data = {
        scanId: "test-scan-id",
        fileName: "test.apk",
        tfScore: 85,
        findings: {},
      };

      const pdfBuffer = await (processor as any).generatePDFReport(data);
      expect(pdfBuffer).toBeInstanceOf(Buffer);
    });
  });
});
