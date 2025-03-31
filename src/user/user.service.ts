import {
  Injectable,
  BadRequestException,
  InternalServerErrorException,
  NotFoundException,
} from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import { UpdateUserDto } from "./dto/update-user.dto";
import { v4 as uuidv4 } from "uuid";
import { UpdatePasswordDto } from "./dto/update-password.dto";

@Injectable()
export class UserService {
  constructor(private readonly supabaseService: SupabaseService) {}

  /**
   * Get user by ID
   */
  async getUserById(userId: string) {
    const { data, error } = await this.supabaseService
      .getAdminClient()
      .auth.admin.getUserById(userId);

    if (error || !data?.user) {
      throw new NotFoundException("User not found");
    }

    return data.user;
  }

  /**
   * Update user details
   */
  async updateUser(userId: string, updateUserDto: UpdateUserDto) {
    const { email, name } = updateUserDto;

    const { data, error } = await this.supabaseService
      .getAdminClient()
      .auth.admin.updateUserById(userId, {
        email,
        user_metadata: { name },
      });

    if (error) {
      throw new InternalServerErrorException(
        `Failed to update user: ${error.message}`
      );
    }

    return { message: "User updated successfully", user: data.user };
  }

  /**
   * Upload profile picture
   */
  async uploadProfilePicture(userId: string, file: Express.Multer.File) {
    if (!file) {
      throw new BadRequestException("No file uploaded");
    }

    const allowedExtensions = ["jpg", "jpeg", "png"];
    const fileExtension =
      (file.originalname ?? "").split(".").pop()?.toLowerCase() || "";

    if (!allowedExtensions.includes(fileExtension)) {
      throw new BadRequestException(
        `Invalid file type. Only ${allowedExtensions.join(", ")} files are allowed.`
      );
    }

    const fileName = `${uuidv4()}.${fileExtension}`;
    const filePath = `profile-pictures/${userId}/${fileName}`;

    try {
      // Upload file to Supabase Storage
      const { error: uploadError } = await this.supabaseService
        .getAdminClient()
        .storage.from("user-assets")
        .upload(filePath, file.buffer, { contentType: file.mimetype });

      if (uploadError) {
        throw new InternalServerErrorException(
          `Failed to upload profile picture: ${uploadError.message}`
        );
      }

      // Get Public URL
      const { data } = this.supabaseService
        .getAdminClient()
        .storage.from("user-assets")
        .getPublicUrl(filePath);
      const pictureUrl = data.publicUrl;

      // Update user metadata with new profile picture URL
      const { error: updateError } = await this.supabaseService
        .getAdminClient()
        .auth.admin.updateUserById(userId, {
          user_metadata: { picture: pictureUrl },
        });

      if (updateError) {
        throw new InternalServerErrorException(
          `Failed to update user profile picture: ${updateError.message}`
        );
      }

      return { message: "Profile picture uploaded successfully", pictureUrl };
    } catch (error) {
      throw new InternalServerErrorException(
        `Failed to upload profile picture: ${error.message}`
      );
    }
  }

  /**
   * Update user password
   */
  async updatePassword(userId: string, updatePasswordDto: UpdatePasswordDto) {
    const { currentPassword, newPassword } = updatePasswordDto;

    // Retrieve the user's email address
    const { data: userData, error: userError } = await this.supabaseService
      .getAdminClient()
      .auth.admin.getUserById(userId);

    if (userError || !userData?.user) {
      throw new BadRequestException("User not found");
    }

    const userEmail = userData.user.email;

    // Verify the current password
    const { data: signInData, error: signInError } = await this.supabaseService
      .getAdminClient()
      .auth.signInWithPassword({
        email: userEmail || "", // Use the user's email address or fallback to an empty string
        password: currentPassword,
      });

    if (signInError || !signInData) {
      throw new BadRequestException("Current password is incorrect");
    }

    // Update the password
    const { error: updateError } = await this.supabaseService
      .getAdminClient()
      .auth.admin.updateUserById(userId, {
        password: newPassword,
      });

    if (updateError) {
      throw new InternalServerErrorException(
        `Failed to update password: ${updateError.message}`
      );
    }

    return { message: "Password updated successfully" };
  }
}
