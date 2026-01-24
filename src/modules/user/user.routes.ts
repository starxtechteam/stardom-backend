import express from "express";
import {
  userProfile,
  userProfileUpdate,
  updateSocialMedia,
  changeMailStep1,
  changeMailStep2,
  changeMailStep3,
  changePassword,
  changePasswordVerifyOTP,
  generatePresignedUrl,
  updateAvatarUrl
} from "./user.controller.ts";
import { verifyToken, roleAuth } from "../../middlewares/auth.ts";
import {
  updateProfileValidation,
  updateSocialValidation,
  changeEmailValidation,
  changeEmailValidation2,
  changePasswordValidation,
  changePasswordVerify
} from "./user.validation.ts";

const router = express.Router();
router.use(verifyToken, roleAuth("user"));

/**
 * @swagger
 * /api/v1/user/presigned-url:
 *   post:
 *     summary: Generate Presigned URL for file upload
 *     description: |
 *       Generate a presigned URL for uploading files to AWS S3.
 *       This URL allows direct browser uploads to S3 without exposing AWS credentials.
 *       
 *       **Supported file types:**
 *       - image/jpeg
 *       - image/png
 *       - image/webp
 *       - image/gif
 *       
 *       **Response includes:**
 *       - uploadUrl: AWS presigned URL for file upload
 *       - fileKey: S3 object key for tracking the upload
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - mimeType
 *             properties:
 *               mimeType:
 *                 type: string
 *                 enum: [image/jpeg, image/png, image/webp, image/gif]
 *                 example: image/jpeg
 *     responses:
 *       200:
 *         description: Presigned URL generated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 uploadUrl:
 *                   type: string
 *                   format: uri
 *                   description: AWS S3 presigned URL for uploading the file
 *                 fileKey:
 *                   type: string
 *                   description: S3 object key for the uploaded file
 *       400:
 *         description: mimeType is required or unsupported file type
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       429:
 *         description: Too many requests
 */
router.post("/presigned-url", generatePresignedUrl);

/**
 * @swagger
 * /api/v1/user/profile:
 *   get:
 *     summary: Get user profile
 *     description: |
 *       Retrieve the authenticated user's complete profile information.
 *       Data is cached in Redis for 5 minutes for performance optimization.
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *           example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         description: JWT Bearer access token
 *     responses:
 *       200:
 *         description: User profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     username:
 *                       type: string
 *                     first_name:
 *                       type: string
 *                     last_name:
 *                       type: string
 *                     bio:
 *                       type: string
 *                     avatarUrl:
 *                       type: string
 *                       format: uri
 *                     bannerUrl:
 *                       type: string
 *                       format: uri
 *                     isVerified:
 *                       type: boolean
 *                     status:
 *                       type: string
 *                       enum: [active, inactive, suspended]
 *                     isPremium:
 *                       type: boolean
 *                     premiumEnds:
 *                       type: string
 *                       format: date-time
 *                     createdAt:
 *                       type: string
 *                       format: date-time
 *                     profile:
 *                       type: object
 *                       properties:
 *                         gender:
 *                           type: string
 *                         birthdate:
 *                           type: string
 *                           format: date
 *                         location:
 *                           type: string
 *                         websiteUrl:
 *                           type: string
 *                           format: uri
 *                         socialTwitter:
 *                           type: string
 *                           format: uri
 *                         socialFacebook:
 *                           type: string
 *                           format: uri
 *                         socialLinkedin:
 *                           type: string
 *                           format: uri
 *                         socialInstagram:
 *                           type: string
 *                           format: uri
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       404:
 *         description: User not found
 */
router.get("/profile", userProfile);

/**
 * @swagger
 * /api/v1/user/profile:
 *   put:
 *     summary: Update user profile
 *     description: |
 *       Update the authenticated user's profile information including basic details and profile attributes.
 *       Supports updating username, name fields, bio, avatar, banner, and profile details.
 *       Username uniqueness is validated before update.
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *           example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         description: JWT Bearer access token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: john_doe
 *               first_name:
 *                 type: string
 *                 example: John
 *               last_name:
 *                 type: string
 *                 example: Doe
 *               bio:
 *                 type: string
 *                 example: Software developer and tech enthusiast
 *               avatarUrl:
 *                 type: string
 *                 format: uri
 *                 example: https://example.com/avatar.jpg
 *               bannerUrl:
 *                 type: string
 *                 format: uri
 *                 example: https://example.com/banner.jpg
 *               gender:
 *                 type: string
 *                 enum: [male, female, other]
 *               birthdate:
 *                 type: string
 *                 format: date
 *                 example: "1990-01-15"
 *               location:
 *                 type: string
 *                 example: San Francisco, CA
 *     responses:
 *       200:
 *         description: Profile updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *       400:
 *         description: Username already taken or invalid input
 *       401:
 *         description: Unauthorized - missing or invalid token
 */
router.put("/profile", updateProfileValidation, userProfileUpdate);

/**
 * @swagger
 * /api/v1/user/profile/avatar:
 *   put:
 *     summary: Update user avatar
 *     description: |
 *       Update the user's avatar image after uploading to AWS S3.
 *       
 *       **Workflow:**
 *       1. Call `/presigned-url` to get upload URL
 *       2. Upload image to S3 using the presigned URL
 *       3. Call this endpoint with the fileKey to confirm and set avatar
 *       
 *       **Validation checks:**
 *       - fileKey must exist and belong to authenticated user
 *       - File must be uploaded from same IP address
 *       - File must be in CREATED status (not already used)
 *       - File upload link must not be expired (10 minute validity)
 *       - File must exist in AWS S3
 *       - User account must be active
 *       
 *       **Response:**
 *       - Updates user's avatarUrl
 *       - Marks file as USED in database
 *       - Automatically cleans up old avatar records
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - fileKey
 *             properties:
 *               fileKey:
 *                 type: string
 *                 description: S3 file key from presigned-url response
 *                 example: "uploads/user123/avatar-1234567890.jpg"
 *     responses:
 *       200:
 *         description: Avatar updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 avatarUrl:
 *                   type: string
 *                   format: uri
 *                   description: CDN URL of the new avatar image
 *       400:
 *         description: Invalid file key, upload expired, or file not found in S3
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Account not active
 *       404:
 *         description: User not found
 *       409:
 *         description: File already used or in processing
 */
router.put("/profile/avatar", updateAvatarUrl);

/**
 * @swagger
 * /api/v1/user/social-links:
 *   put:
 *     summary: Update social media links
 *     description: |
 *       Update the user's social media profile links and website URL.
 *       At least one field must be provided for the update.
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *           example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         description: JWT Bearer access token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               websiteUrl:
 *                 type: string
 *                 format: uri
 *                 example: https://johndoe.com
 *               socialTwitter:
 *                 type: string
 *                 format: uri
 *                 example: https://twitter.com/johndoe
 *               socialFacebook:
 *                 type: string
 *                 format: uri
 *                 example: https://facebook.com/johndoe
 *               socialLinkedin:
 *                 type: string
 *                 format: uri
 *                 example: https://linkedin.com/in/johndoe
 *               socialInstagram:
 *                 type: string
 *                 format: uri
 *                 example: https://instagram.com/johndoe
 *     responses:
 *       200:
 *         description: Social links updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *       400:
 *         description: No social media fields provided or invalid input
 *       401:
 *         description: Unauthorized - missing or invalid token
 */
router.put("/social-links", updateSocialValidation, updateSocialMedia);

/**
 * @swagger
 * /api/v1/user/change-email:
 *   post:
 *     summary: Change email step 1 - Request OTP
 *     description: |
 *       Initiate email change process by providing a new email address.
 *       An OTP will be sent to the new email. Only one email change per 24 hours allowed.
 *       Validation checks:
 *       - Email must be unique
 *       - User account must be active
 *       - Cannot change to current email
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *           example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         description: JWT Bearer access token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: newemail@example.com
 *     responses:
 *       200:
 *         description: OTP sent to new email address
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 token:
 *                   type: string
 *                   description: Temporary token for OTP verification (valid 10 minutes)
 *       400:
 *         description: Invalid email or email change session already in progress
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Account is not active
 *       404:
 *         description: User not found
 *       409:
 *         description: Email already in use or email same as current
 *       429:
 *         description: Can only change email once every 24 hours
 */
router.post("/change-email", changeEmailValidation, changeMailStep1);

/**
 * @swagger
 * /api/v1/user/change-email/verify:
 *   post:
 *     summary: Change email step 2 - Verify OTP on new email
 *     description: |
 *       Verify the OTP sent to the new email address.
 *       After successful verification, a new OTP will be sent to the old email for final confirmation.
 *       Maximum 5 invalid attempts allowed.
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *           example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         description: JWT Bearer access token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - otp
 *               - token
 *             properties:
 *               otp:
 *                 type: string
 *                 minLength: 6
 *                 maxLength: 6
 *                 example: "123456"
 *               token:
 *                 type: string
 *                 description: Token from change-email step 1
 *     responses:
 *       200:
 *         description: OTP verified, new OTP sent to old email
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 token:
 *                   type: string
 *       400:
 *         description: Invalid or expired OTP/token
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Account not active
 *       429:
 *         description: Too many invalid attempts (max 5)
 */
router.post("/change-email/verify", changeEmailValidation2, changeMailStep2);

/**
 * @swagger
 * /api/v1/user/change-email/update:
 *   post:
 *     summary: Change email step 3 - Verify old email and complete change
 *     description: |
 *       Final step: Verify the OTP sent to the old email address to confirm email change.
 *       After successful verification, the email is updated and email change history is recorded.
 *       Maximum 5 invalid attempts allowed.
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *           example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         description: JWT Bearer access token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - otp
 *               - token
 *             properties:
 *               otp:
 *                 type: string
 *                 minLength: 6
 *                 maxLength: 6
 *                 example: "123456"
 *               token:
 *                 type: string
 *                 description: Token from change-email/verify step
 *     responses:
 *       200:
 *         description: Email updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *       400:
 *         description: Invalid OTP/token or email change session expired
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Account not active
 *       429:
 *         description: Too many invalid attempts (max 5)
 */
router.post("/change-email/update", changeEmailValidation2, changeMailStep3);

/**
 * @swagger
 * /api/v1/user/change-password:
 *   post:
 *     summary: Change password
 *     description: |
 *       Initiate password change process.
 *       If 2FA is NOT enabled: Password is changed immediately.
 *       If 2FA IS enabled: OTP is sent to email for verification (requires step 2).
 *       Validation:
 *       - Old password must be correct
 *       - New password must be different from old password
 *       - New password must be at least 8 characters
 *       - Only one active password change request allowed at a time
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *           example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         description: JWT Bearer access token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - oldPassword
 *               - newPassword
 *               - confPassword
 *             properties:
 *               oldPassword:
 *                 type: string
 *                 format: password
 *                 minLength: 1
 *               newPassword:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 example: NewSecurePass123!
 *               confPassword:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 example: NewSecurePass123!
 *     responses:
 *       200:
 *         description: Password changed successfully (if 2FA disabled) or OTP sent (if 2FA enabled)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 token:
 *                   type: string
 *                   description: Present only if 2FA enabled (valid 5 minutes)
 *       400:
 *         description: Invalid old password, weak password, or same as current
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Account not active
 *       404:
 *         description: User not found
 *       429:
 *         description: OTP already sent, please wait before trying again
 */
router.post("/change-password", changePasswordValidation, changePassword);

/**
 * @swagger
 * /api/v1/user/change-password/verify:
 *   post:
 *     summary: Verify password change with OTP
 *     description: |
 *       Final step for password change when 2FA is enabled.
 *       Verify the OTP sent to email to complete password change.
 *       Maximum 5 invalid attempts allowed.
 *       Password change must have been initiated within the last 5 minutes.
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: header
 *         name: Authorization
 *         required: true
 *         schema:
 *           type: string
 *           example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         description: JWT Bearer access token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - otp
 *               - token
 *             properties:
 *               otp:
 *                 type: string
 *                 minLength: 6
 *                 maxLength: 6
 *                 example: "123456"
 *               token:
 *                 type: string
 *                 description: Token from change-password step 1
 *     responses:
 *       200:
 *         description: OTP verified, password changed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *       400:
 *         description: Invalid OTP/token or password change session expired
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Account not active
 *       404:
 *         description: User not found
 *       429:
 *         description: Too many invalid attempts (max 5)
 */
router.post("/change-password/verify", changePasswordVerify, changePasswordVerifyOTP);

export default router;