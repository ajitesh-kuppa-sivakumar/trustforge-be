import { Module } from "@nestjs/common";

import { SupabaseService } from "../supabase/supabase.service";
import { UserController } from "./user.controller";
import { UserService } from "./user.service";

@Module({
  controllers: [UserController],
  providers: [UserService, SupabaseService],
  exports: [UserService],
})
export class UserModule {}
