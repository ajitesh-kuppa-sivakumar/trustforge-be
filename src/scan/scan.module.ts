import { Module } from "@nestjs/common";
import { BullModule } from "@nestjs/bull";
import { ScanController } from "./scan.controller";
import { ScanService } from "./scan.service";
import { ScanProcessor } from "./scan.processor";

@Module({
  imports: [
    BullModule.registerQueue({
      name: "scan", // Register the "scan" queue
    }),
  ],
  controllers: [ScanController],
  providers: [ScanService, ScanProcessor],
})
export class ScanModule {}
