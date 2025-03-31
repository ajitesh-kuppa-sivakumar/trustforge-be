import {
  Controller,
  Patch,
  Get,
  Body,
  UseGuards,
  HttpCode,
  HttpStatus,
  UploadedFile,
  UseInterceptors,
  BadRequestException,
} from "@nestjs/common";
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiConsumes,
  ApiBody,
} from "@nestjs/swagger";
import { FileInterceptor } from "@nestjs/platform-express";
import { UpdateUserDto } from "./dto/update-user.dto";
import { SupabaseAuthGuard } from "../common/guards/supabase-auth.guard";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { UserService } from "./user.service";
import { FileUploadDto } from "../scan/dto/file-upload.dto";
import { UpdatePasswordDto } from "./dto/update-password.dto";

@ApiTags("User")
@Controller("user")
@UseGuards(SupabaseAuthGuard)
@ApiBearerAuth()
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Patch("update")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Update user details" })
  @ApiResponse({
    status: 200,
    description: "User details updated successfully",
  })
  @ApiResponse({ status: 400, description: "Bad request" })
  async updateUser(
    @Body() updateUserDto: UpdateUserDto,
    @CurrentUser() user: any
  ) {
    return this.userService.updateUser(user.id, updateUserDto);
  }

  @Patch("upload-picture")
  @UseInterceptors(FileInterceptor("file"))
  @ApiConsumes("multipart/form-data")
  @ApiBody({ type: FileUploadDto })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Upload profile picture" })
  @ApiResponse({
    status: 200,
    description: "Profile picture uploaded successfully",
  })
  @ApiResponse({ status: 400, description: "Invalid file type" })
  async uploadProfilePicture(
    @UploadedFile() file: Express.Multer.File,
    @CurrentUser() user: any
  ) {
    if (!file) {
      throw new BadRequestException("No file uploaded");
    }

    return this.userService.uploadProfilePicture(user.id, file);
  }

  @Patch("update-password")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Update user password" })
  @ApiResponse({
    status: 200,
    description: "Password updated successfully",
  })
  @ApiResponse({ status: 400, description: "Bad request" })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  async updatePassword(
    @Body() updatePasswordDto: UpdatePasswordDto,
    @CurrentUser() user: any
  ) {
    return this.userService.updatePassword(user.id, updatePasswordDto);
  }

  @Get("me")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Get current user details" })
  @ApiResponse({
    status: 200,
    description: "User details retrieved successfully",
  })
  @ApiResponse({ status: 401, description: "Unauthorized" })
  async getCurrentUser(@CurrentUser() user: any) {
    return this.userService.getUserById(user.id);
  }
}
