import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

@Injectable()
export class SupabaseService {
  private adminClient: SupabaseClient;
  private readonly logger = new Logger(SupabaseService.name);

  constructor(private configService: ConfigService) {
    const supabaseUrl = this.configService.get<string>("SUPABASE_URL");
    const supabaseServiceKey = this.configService.get<string>(
      "SUPABASE_SERVICE_KEY"
    );

    if (!supabaseUrl || !supabaseServiceKey) {
      this.logger.error(
        "❌ Supabase URL or Service Key is missing. Check your environment variables."
      );
      throw new Error("Supabase URL or Service Key is not defined.");
    }

    this.adminClient = createClient(supabaseUrl, supabaseServiceKey);
    this.logger.log("✅ Supabase client initialized successfully.");
  }

  getAdminClient(): SupabaseClient {
    return this.adminClient;
  }

  /**
   * Ensures that the specified bucket exists in Supabase Storage.
   * If the bucket doesn't exist, it will be created.
   */
  async ensureBucketExists(bucketName: string): Promise<void> {
    this.logger.debug(`Checking if bucket "${bucketName}" exists...`);

    const { data: buckets, error } =
      await this.adminClient.storage.listBuckets();
    if (error) {
      this.logger.error(`Failed to list buckets: ${error.message}`);
      throw new Error(`Failed to list buckets: ${error.message}`);
    }

    const bucketExists = buckets.some((bucket) => bucket.name === bucketName);
    if (bucketExists) {
      this.logger.debug(`✅ Bucket "${bucketName}" already exists.`);
      return;
    }

    this.logger.log(`🚀 Creating bucket "${bucketName}"...`);
    const { error: createError } = await this.adminClient.storage.createBucket(
      bucketName,
      {
        public: true, // Ensure the bucket is public if needed
      }
    );

    if (createError) {
      this.logger.error(`❌ Failed to create bucket: ${createError.message}`);
      throw new Error(`Failed to create bucket: ${createError.message}`);
    }

    this.logger.log(`✅ Bucket "${bucketName}" created successfully.`);
  }
}
