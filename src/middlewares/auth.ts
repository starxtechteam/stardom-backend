import jwt from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";
import type { JwtPayload as JwtLibPayload } from "jsonwebtoken";

import type { JwtPayload } from "../types/jwt.types.ts";
import type { AuthSession } from "../types/auth.types.ts";

import { ENV } from "../config/env.ts";
import { asyncHandler } from "../utils/async-handler.ts";
import { ApiError } from "../utils/api-error.ts";
import { REDIS_KEYS, redisClient } from "../config/redis.config.ts";
import { prisma } from "../config/prisma.config.ts";
import { getClientIp } from "../modules/auth/auth.service.ts";

declare global {
  namespace Express {
    interface Request {
      session?: AuthSession;
    }
  }
}

type AuthType = "user" | "admin";

export const createVerifyToken = (type: AuthType) =>
  asyncHandler(async (req: Request, _res: Response, next: NextFunction) => {
    /* ========== AUTH HEADER ========== */
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      throw new ApiError(401, "Unauthorized");
    }

    const token = authHeader.slice(7).trim();

    if (!token) {
      throw new ApiError(401, "Unauthorized");
    }

    /* ========== BLACKLIST ========== */
    const isBlacklisted = await redisClient.get(
      REDIS_KEYS.blacklistToken(token),
    );

    if (isBlacklisted) {
      throw new ApiError(401, "Token revoked");
    }

    /* ========== JWT VERIFY ========== */
    const secret =
      type === "admin" ? ENV.JWT_ADMIN_ACCESS_SECRET : ENV.JWT_ACCESS_SECRET;

    let decoded: JwtPayload;

    try {
      decoded = jwt.verify(token, secret) as JwtPayload & JwtLibPayload;
    } catch (err: any) {
      if (err instanceof jwt.TokenExpiredError) {
        throw new ApiError(401, "Token expired");
      }

      throw new ApiError(401, "Invalid token");
    }

    if (!decoded?.sessionId || !decoded?.role) {
      throw new ApiError(401, "Invalid token payload");
    }

    /* ========== FETCH SESSION ========== */
    let sessionDb: any;

    if (type === "user") {
      sessionDb = await prisma.userSession.findUnique({
        where: { id: decoded.sessionId },
        select: {
          id: true,
          userId: true,
          deviceName: true,
          deviceType: true,
          os: true,
          browser: true,
          ipAddress: true,
          revokedAt: true,
          expiresAt: true,
        },
      });
    } else {
      sessionDb = await prisma.adminSession.findUnique({
        where: { id: decoded.sessionId },
        select: {
          id: true,
          adminId: true,
          deviceName: true,
          deviceType: true,
          os: true,
          browser: true,
          ipAddress: true,
          revokedAt: true,
          expiresAt: true,
        },
      });
    }

    /* ========== VALIDATE SESSION ========== */
    if (!sessionDb || sessionDb.revokedAt || sessionDb.expiresAt < new Date()) {
      throw new ApiError(401, "Session expired");
    }

    /* ========== IP CHECK ========== */
    const ip = getClientIp(req);

    if (!ip || sessionDb.ipAddress !== ip) {
      throw new ApiError(401, "Session validation failed. Please login again.");
    }

    /* ========== ATTACH SESSION ========== */

    const session: AuthSession = {
      id: sessionDb.id,
      userId: type === "admin" ? sessionDb.adminId : sessionDb.userId,
      deviceName: sessionDb.deviceName,
      deviceType: sessionDb.deviceType,
      os: sessionDb.os,
      browser: sessionDb.browser,
      ipAddress: sessionDb.ipAddress,
      role: decoded.role as "user" | "admin",
      token,
    };

    req.session = session;

    next();
  });