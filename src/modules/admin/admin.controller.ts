import { asyncHandler } from "../../utils/async-handler.js";
import { ApiError } from "../../utils/api-error.js";
import { prisma } from "../../config/prisma.config.ts";
import bcrypt from "bcryptjs";
import { generateOTP, generateToken, verifyOTP } from "../../utils/core.ts";
import { getClientIp, getDeviceInfo } from "../auth/auth.service.ts";
import { sendAdminLoginOtp } from "../../mails/admin/sendLoginOtp.ts";
import { hashValue, loginTokens } from "./admin.service.ts";
import { setAuthCookie } from "./admin.service.ts";

const MAXIMUM_LOGGEDIN_DEVICE = 5;

export const adminLogin = asyncHandler(async (req, res) => {
  const { identifier, password } = req.body;

  const user = await prisma.user.findFirst({
    where: {
      OR: [{ username: identifier }, { email: identifier }],
    },
    include: {
      admin: true,
    },
  });

  if (!user || !user.admin) {
    throw new ApiError(403, "Invalid credentials");
  }

  const isValid = await bcrypt.compare(password, user.password);

  if (!isValid) {
    throw new ApiError(403, "Invalid credentials");
  }

  if (user.status !== "active") {
    throw new ApiError(403, `Account ${user.status}`);
  }

  if (!user.admin.isApproved || user.admin.status !== "active") {
    throw new ApiError(403, "Admin not allowed");
  }

  const admin = user.admin;
  const ip = getClientIp(req);

  const sessionCount = await prisma.adminSession.count({
    where: {
      adminId: admin.id,
      expiresAt: { gt: new Date() },
    },
  });

  if (sessionCount >= MAXIMUM_LOGGEDIN_DEVICE) {
    throw new ApiError(429, "Too many active devices");
  }

  const totp = await prisma.adminTotp.findFirst({
    where: { adminId: admin.id },
    select: { enabled: true },
  });

  if (!totp?.enabled) {
    const device = getDeviceInfo(req);

    const tokens = await loginTokens({
      adminId: admin.id,
      ip,
      device: {
        name: device.deviceName,
        type: device.deviceType,
        os: device.os,
        browser: device.browser,
      },
    });

    setAuthCookie(res, tokens.accessToken);

    return res.json({
      success: true,
      message: "Admin logged in",
      refreshToken: tokens.refreshToken,
    });
  }

  const activeOtp = await prisma.adminOtp.findFirst({
    where: {
      adminId: admin.id,
      purpose: "ADMIN_LOGIN",
      expiresAt: { gt: new Date() },
    },
  });

  if (activeOtp) {
    throw new ApiError(429, "OTP already sent. Try later.");
  }

  const { otp, otpHash } = generateOTP();
  const { token, tokenHash } = generateToken();

  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  await prisma.$transaction([
    prisma.adminOtp.create({
      data: {
        adminId: admin.id,
        purpose: "ADMIN_LOGIN",
        codeHash: otpHash,
        expiresAt,
      },
    }),

    prisma.adminTokenHash.create({
      data: {
        tokenHash,
        userIp: ip,
        adminId: admin.id,
        expiresAt,
      },
    }),
  ]);

  const sent = await sendAdminLoginOtp({
    email: user.email,
    otp,
    expiresIn: 5,
  });

  if (!sent) {
    throw new ApiError(500, "Failed to send OTP");
  }

  return res.json({
    success: true,
    authentication: true,
    message: "OTP sent to your email",
    token,
  });
});

export const adminLoginOtpVerify = asyncHandler(async (req, res) => {
  const { token, otp } = req.body;

  const ip = getClientIp(req);
  const tokenHash = hashValue(token);

  const storedToken = await prisma.adminTokenHash.findFirst({
    where: {
      tokenHash,
      expiresAt: { gt: new Date() },
    },
  });

  if (!storedToken || storedToken.userIp !== ip) {
    throw new ApiError(400, "Invalid or expired token");
  }

  const storedOtp = await prisma.adminOtp.findFirst({
    where: {
      adminId: storedToken.adminId,
      purpose: "ADMIN_LOGIN",
      expiresAt: { gt: new Date() },
    },
  });

  if (!storedOtp) {
    throw new ApiError(400, "OTP expired");
  }

  const isValidOtp = verifyOTP(otp, storedOtp.codeHash);
  if (!isValidOtp) {
    throw new ApiError(400, "Invalid OTP");
  }

  await prisma.$transaction([
    prisma.adminOtp.delete({ where: { id: storedOtp.id } }),
    prisma.adminTokenHash.delete({ where: { id: storedToken.id } }),
  ]);

  const device = getDeviceInfo(req);

  const tokens = await loginTokens({
    adminId: storedOtp.adminId,
    ip,
    device: {
      name: device.deviceName,
      type: device.deviceType,
      os: device.os,
      browser: device.browser,
    },
  });

  setAuthCookie(res, tokens.accessToken);

  return res.json({
    success: true,
    message: "Admin logged in",
    refreshToken: tokens.refreshToken,
  });
});

// export const assignAdmin = asyncHandler(async(req, res) => {
//     const { userId, role } = req.body;
// })
