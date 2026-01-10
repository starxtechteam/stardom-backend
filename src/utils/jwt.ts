import jwt from "jsonwebtoken";
import type { SignOptions } from "jsonwebtoken";
import { ENV } from "../config/env.js";
import type { JwtPayload } from "../types/jwt.types.js";

export const signAccessToken = (payload: JwtPayload) => {
  return jwt.sign(payload as object, ENV.JWT_ACCESS_SECRET, {
    expiresIn: ENV.JWT_ACCESS_EXPIRES_IN,
  } as SignOptions);
};

export const signRefreshToken = (payload: JwtPayload) => {
  return jwt.sign(payload as object, ENV.JWT_REFRESH_SECRET, {
    expiresIn: ENV.JWT_REFRESH_EXPIRES_IN,
  } as SignOptions);
};

export const verifyAccessToken = (token: string) => {
  return jwt.verify(token, ENV.JWT_ACCESS_SECRET) as JwtPayload;
};

export const verifyRefreshToken = (token: string) => {
  return jwt.verify(token, ENV.JWT_REFRESH_SECRET) as JwtPayload;
};
