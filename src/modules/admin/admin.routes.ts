import express from "express";
import { adminLogin, adminLoginOtpVerify } from "./admin.controller.ts";
import { authRateLimit } from "../../middlewares/ratelimit.ts";

const router = express.Router();

/**
 * @swagger
 * /api/v1/admin/login:
 *   post:
 *     summary: Admin login
 *     description: |
 *       Authenticate an admin user using email/username and password.
 *       Returns access and refresh tokens on success.
 *     tags: [Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - identifier
 *               - password
 *             properties:
 *               identifier:
 *                 type: string
 *                 description: Email or username of the admin
 *                 example: admin@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 description: Admin account password
 *     responses:
 *       200:
 *         description: Authenticated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 accessToken:
 *                   type: string
 *                 refreshToken:
 *                   type: string
 *       400:
 *         description: Missing or invalid input
 *       401:
 *         description: Invalid credentials
 *       429:
 *         description: Too many requests (rate limited)
 */
router.post("/login", authRateLimit, adminLogin);

/**
 * @swagger
 * /api/v1/admin/login/otp-verify:
 *   post:
 *     summary: Verify admin login OTP
 *     description: |
 *       Verify the OTP sent during admin login when MFA/OTP is required.
 *       Accepts a temporary token (from initial login) and the OTP code.
 *     tags: [Admin]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - otp
 *             properties:
 *               token:
 *                 type: string
 *                 description: Temporary token from initial login step
 *               otp:
 *                 type: string
 *                 minLength: 4
 *                 maxLength: 8
 *                 description: One-time password sent to admin
 *     responses:
 *       200:
 *         description: OTP verified, authenticated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 accessToken:
 *                   type: string
 *                 refreshToken:
 *                   type: string
 *       400:
 *         description: Missing or invalid input
 *       401:
 *         description: Invalid or expired OTP/token
 *       429:
 *         description: Too many attempts
 */
router.post("/login/otp-verify", authRateLimit, adminLoginOtpVerify);

export default router;