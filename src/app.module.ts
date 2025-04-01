import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { ThrottlerModule } from "@nestjs/throttler";
import { BullModule } from "@nestjs/bull";
import { AuthModule } from "./auth/auth.module";
import { ScanModule } from "./scan/scan.module";
import { SupabaseModule } from "./supabase/supabase.module";
import { ReportModule } from "./report/report.module";
import { UserModule } from "./user/user.module";
import { DashboardModule } from "./dashboard/dashboard.module";

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60,
        limit: 10,
      },
    ]),
    BullModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        redis: {
          host: configService.get<string>("REDIS_HOST", "localhost"),
          port: configService.get<number>("REDIS_PORT", 6379),
        },
      }),
      inject: [ConfigService],
    }),
    BullModule.registerQueue({
      name: "scan", // Register the "scan" queue
    }),
    SupabaseModule,
    AuthModule,
    ScanModule,
    ReportModule,
    UserModule,
    DashboardModule,
  ],
})
export class AppModule {}
