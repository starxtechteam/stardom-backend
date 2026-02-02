import express from "express";
import authRoutes from "../modules/auth/auth.routes.js";
import userRoutes from "../modules/user/user.routes.ts";
import adminRoutes from "../modules/admin/admin.routes.ts";
const router = express.Router();

/**
 * @swagger
 * tags:
 *   - name: Authentication
 *     description: |
 *       Authentication endpoints for user registration, login, and password management.
 *       - **Registration Flow**: Email OTP → Verify OTP → Account Created
 *       - **Login Flow**: Email OTP → Verify OTP → JWT Tokens
 *       - **Password Reset**: Request OTP → Verify OTP → Set New Password
 *   - name: User
 *     description: |
 *       User profile management endpoints.
 *       - View and update profile information
 *       - Manage social media links
 *       - Change email and password with verification
 *   - name: "2FA"
 *     description: |
 *       Two-factor authentication endpoints for enhanced security.
 *       - Enable 2FA with OTP
 *       - Verify 2FA tokens
 *   - name: "Admin"
 *     description: |
 *       Authentication endpoints for user registration, login, and password management.
 *       - Login
 */

router.use('/auth', authRoutes);
router.use('/user', userRoutes);
router.use('/admin', adminRoutes);

export default router;