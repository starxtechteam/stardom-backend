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

export const verifyToken = asyncHandler(
  async (req: Request, _res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      throw new ApiError(401, "Unauthorized");
    }

    const token = authHeader.slice(7).trim();
    if (!token) {
      throw new ApiError(401, "Unauthorized");
    }

    // 🔐 Blacklist check (logout / forced revoke)
    const isBlacklisted = await redisClient.get(
      REDIS_KEYS.blacklistToken(token),
    );
    if (isBlacklisted) {
      throw new ApiError(401, "Unauthorized");
    }

    let decoded: JwtPayload;

    try {
      decoded = jwt.verify(token, ENV.JWT_ACCESS_SECRET) as JwtLibPayload &
        JwtPayload;
    } catch (err: unknown) {
      if (err instanceof jwt.TokenExpiredError) {
        throw new ApiError(401, "Token expired");
      }

      throw new ApiError(401, "Invalid token");
    }

    if (!decoded?.sessionId || !decoded?.role) {
      throw new ApiError(401, "Invalid token");
    }

    const userSession = await prisma.userSession.findUnique({
      where: { id: decoded.sessionId },
      select: {
        id: true,
        userId: true,
        deviceName: true,
        ipAddress: true,
        userAgent: true,
        revokedAt: true,
      },
    });

    if (!userSession || userSession.revokedAt) {
      throw new ApiError(401, "Session expired");
    }

    const ip = getClientIp(req)?.trim();

    if (!ip || userSession.ipAddress !== ip) {
      throw new ApiError(
        401,
        "Session validation failed. Please log in again.",
      );
    }

    const authSession: AuthSession = {
      id: userSession.id,
      userId: userSession.userId,
      deviceName: userSession.deviceName,
      ipAddress: userSession.ipAddress,
      userAgent: userSession.userAgent,
      role: decoded.role as "user" | "admin",
    };

    req.session = authSession;
    next();
  },
);

export const roleAuth = (...roles: Array<"user" | "admin">) =>
  asyncHandler(async (req: Request, _res: Response, next: NextFunction) => {
    const role = req.session?.role;

    if (!role || !roles.includes(role)) {
      throw new ApiError(403, "Forbidden");
    }

    next();
  });
