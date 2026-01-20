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

    if (!authHeader?.startsWith("Bearer ")) {
      throw new ApiError(401, "Authorization token is required");
    }

    const token = authHeader.split(" ")[1];

    const isBlacklisted = await redisClient.get(
      REDIS_KEYS.blacklistToken(token)
    );
    if (isBlacklisted) {
      throw new ApiError(401, "Token revoked");
    }

    let decoded: JwtPayload;

    try {
      decoded = jwt.verify(token, ENV.JWT_ACCESS_SECRET) as JwtLibPayload &
        JwtPayload;
    } catch (err: unknown) {
      let msg = "Invalid token";

      if (err instanceof jwt.TokenExpiredError) {
        msg = "Token expired";
      } else if (err instanceof jwt.JsonWebTokenError) {
        msg = "Invalid token";
      }

      throw new ApiError(401, msg);
    }

    const userSession = await prisma.userSession.findUnique({
      where: { id: decoded.sessionId }
    })
    if(!userSession){
      throw new ApiError(400, "Invalid or expired session");
    }

    const ip = getClientIp(req);
    if(userSession.ipAddress !== ip){
      throw new ApiError(400, "Session IP mismatch. Please re-login for security reasons.")
    }

    const authSession: AuthSession = {
      id: userSession.id,
      userId: userSession.userId,
      deviceName: userSession.deviceName,
      ipAddress: userSession.ipAddress,
      userAgent: userSession.userAgent,
      role: decoded.role as "user" | "admin"
    }

    req.session = authSession;
    next();
  }
);

export const roleAuth = (...roles: Array<"user" | "admin">) =>
  asyncHandler(async (req, _res, next) => {
    if (!req.session || !roles.includes(req.session.role as "user" | "admin")) {
      throw new ApiError(403, "Forbidden");
    }
    next();
  });
