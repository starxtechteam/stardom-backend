import { Request } from "express";
import crypto from "crypto";
import { UAParser } from "ua-parser-js";
import { prisma } from "../../config/prisma.config.ts";
import type { DeviceInfo, LoginAttempts } from "../../types/auth.types.ts";
import jwt from "jsonwebtoken";
import type { SignOptions } from "jsonwebtoken";
import { ENV } from "../../config/env.js";
import type { JwtPayload } from "../../types/jwt.types.js";
import { redisClient, REDIS_KEYS } from "../../config/redis.config.ts";
import { AUTH_OTP } from "../../constants/auth.constants.ts";

const MAX_ATTEMPTS = 5;
const BLOCK_WINDOW_MINUTES = 15;

export const getClientIp = (req: Request): string => {
  let ip =
    (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
    (req.headers["x-real-ip"] as string) ||
    req.ip ||
    req.socket.remoteAddress ||
    "";

  if (!ip) return "unknown";

  // Convert IPv6 localhost
  if (ip === "::1") return "127.0.0.1";

  // Convert IPv6-mapped IPv4 (::ffff:127.0.0.1)
  if (ip.startsWith("::ffff:")) {
    ip = ip.replace("::ffff:", "");
  }

  return ip;
};

export const getDeviceInfo = (req: Request) => {
  const parser = new UAParser(req.headers["user-agent"] as string);
  const result = parser.getResult();

  return {
    deviceName: result.device.model || result.device.type || "Desktop",
    deviceType: result.device.type || "desktop",
    os: `${result.os.name ?? "Unknown"} ${result.os.version ?? ""}`,
    browser: `${result.browser.name ?? "Unknown"} ${
      result.browser.version ?? ""
    }`,
  };
};

export async function saveLoginAttempts(data: LoginAttempts): Promise<void> {
  try {
    await prisma.loginAttempt.create({
      data: {
        identifier: data.identifier,
        ipAddress: data.ipAddress,
        deviceName: data.deviceName,
        deviceType: data.deviceType,
        os: data.os,
        browser: data.browser,
        success: data.success,
        message: data.message,
      },
    });
  } catch (err) {
    console.error("Failed to save login attempt:", err);
  }
}

export async function verifyUserLoginAttempts(
  credential: LoginAttempts,
): Promise<boolean> {
  try {
    const windowStart = new Date(Date.now() - BLOCK_WINDOW_MINUTES * 60 * 1000);

    const failedAttempts = await prisma.loginAttempt.count({
      where: {
        identifier: credential.identifier,
        success: false,
        createdAt: {
          gte: windowStart,
        },
      },
    });

    // 🚫 Block login
    if (failedAttempts >= MAX_ATTEMPTS) {
      return false;
    }

    // ✅ Allow login
    return true;
  } catch (err) {
    console.error("verifyUserLoginStep1 error:", err);
    return false;
  }
}

export const hashValue = (token: string) =>
  crypto.createHash("sha256").update(token).digest("hex");

export const signAccessToken = (payload: JwtPayload) => {
  const token = jwt.sign(payload as object, ENV.JWT_ACCESS_SECRET, {
    expiresIn: ENV.JWT_ACCESS_EXPIRES_IN,
  } as SignOptions);

  return {
    token,
    hash: hashValue(token),
  };
};

export const signRefreshToken = (payload: JwtPayload) => {
  const token = jwt.sign(payload as object, ENV.JWT_REFRESH_SECRET, {
    expiresIn: ENV.JWT_REFRESH_EXPIRES_IN,
  } as SignOptions);

  return {
    token,
    hash: hashValue(token),
  };
};

export const verifyAccessToken = (token: string) => {
  return jwt.verify(token, ENV.JWT_ACCESS_SECRET) as JwtPayload;
};

export const verifyRefreshToken = (token: string) => {
  return jwt.verify(token, ENV.JWT_REFRESH_SECRET) as JwtPayload;
};

export const actualLogin = async (
  userId: string,
  identifier: string,
  device: DeviceInfo,
  ip: string,
): Promise<{ accessToken: string; refreshToken: string }> => {
  const refresh = signRefreshToken({ sessionId: userId, role: "user" });
  const userSession = await prisma.userSession.create({
    data: {
      userId: userId,
      refreshTokenHash: refresh.hash,
      deviceName: device.deviceName,
      ipAddress: ip,
      userAgent: device.deviceType,
      expiresAt: new Date(Date.now() + AUTH_OTP.SESSION_EXPIRE_IN * 86400000),
    },
  });

  const access = signAccessToken({ sessionId: userSession.id, role: "user" });

  await saveLoginAttempts({
    identifier,
    ipAddress: ip,
    deviceName: device.deviceName,
    deviceType: device.deviceType,
    os: device.os,
    browser: device.browser,
    success: true,
    message: "Login successful",
  });

  return { accessToken: access.token, refreshToken: refresh.token };
};

export const invalidateOtp = async (tokenHash: string) => {
  await redisClient.del(REDIS_KEYS.loginOtp(tokenHash));
  await redisClient.del(REDIS_KEYS.otpVerify(tokenHash));
  await redisClient.del(REDIS_KEYS.identifier(tokenHash));
};

/**
 * Log audit events for sensitive security operations
 * @param userId - User ID
 * @param action - Action type (ENABLE_2FA, DISABLE_2FA, LOGOUT_ALL_DEVICES, PASSWORD_RESET, etc.)
 * @param ipAddress - Client IP
 * @param device - Device information
 * @param status - success or failure
 */
export const logAuditEvent = async (
  userId: string,
  action: string,
  ipAddress: string,
  device: DeviceInfo,
  status: "success" | "failure",
): Promise<void> => {
  try {
    // Log to database (if audit table exists) or to console/external service
    console.log(`[AUDIT] ${action} | User: ${userId} | IP: ${ipAddress} | Device: ${device.deviceName} | Status: ${status}`);
    
    // Optional: Store in database if audit table exists
    // await prisma.auditLog.create({...})
  } catch (err) {
    console.error("Failed to log audit event:", err);
  }
};
