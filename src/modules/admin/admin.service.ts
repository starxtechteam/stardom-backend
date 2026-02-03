import { prisma } from "../../config/prisma.config.ts";
import jwt from "jsonwebtoken";
import type { SignOptions } from "jsonwebtoken";
import type { JwtPayload } from "../../types/jwt.types.js";
import { ENV } from "../../config/env.ts";
import crypto from "crypto";
import { ApiError } from "../../utils/api-error.ts";
import type { Response } from "express";

export const hashValue = (token: string) =>
  crypto.createHash("sha256").update(token).digest("hex");

export const signAccessToken = (payload: JwtPayload) => {
  const token = jwt.sign(payload as object, ENV.JWT_ACCESS_SECRET, {
    expiresIn: ENV.JWT_ADMIN_ACCESS_SECRET,
  } as SignOptions);

  return {
    token,
    hash: hashValue(token),
  };
};

export const signRefreshToken = (payload: JwtPayload) => {
  const token = jwt.sign(payload as object, ENV.JWT_REFRESH_SECRET, {
    expiresIn: ENV.JWT_ADMIN_REFRESH_SECRET,
  } as SignOptions);

  return {
    token,
    hash: hashValue(token),
  };
};

type UserLogin = {
  adminId: string;
  ip: string;
  device: {
    name: string;
    type: string;
    os: string;
    browser: string;
  };
};

export async function loginTokens(
  data: UserLogin,
): Promise<{ accessToken: string; refreshToken: string }> {
  const refresh = signRefreshToken({ sessionId: data.adminId, role: "admin" });

  const adminSession = await prisma.adminSession.create({
    data: {
      adminId: data.adminId,
      refreshTokenHash: refresh.hash,
      deviceName: data.device.name,
      deviceType: data.device.type,
      os: data.device.os,
      browser: data.device.browser,
      ipAddress: data.ip,

      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 1000),
    },
  });

  if (!adminSession) {
    throw new ApiError(500, "Faild to login");
  }

  const access = signAccessToken({ sessionId: adminSession.id, role: "admin" });

  return { accessToken: access.token, refreshToken: refresh.token };
}

export function setAuthCookie(res: Response, token: String) {
  const isProd = ENV.NODE_ENV === "production";

  res.cookie("token", token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "strict" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}
