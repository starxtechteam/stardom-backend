import type { Request, Response } from "express";
import { asyncHandler } from "../../utils/async-handler.js";
import { ApiError } from "../../utils/api-error.js";
import { prisma } from "../../config/prisma.config.ts";
import { redisClient, REDIS_KEYS } from "../../config/redis.config.ts";
import bcrypt from "bcryptjs";
import { AUTH_OTP } from "../../constants/auth.constants.ts";
import { sendOtpEmail } from "../../mails/auth/registerOtp.mails.ts";
import { sendWelcomeEmail } from "../../mails/user/welcome.mails.ts";
import {
  generateOTP,
  verifyOTP,
  generateToken,
  verifyToken,
} from "../../utils/core.ts";
import { getClientIp } from "./auth.service.ts";

export const registerStep1 = asyncHandler(
  async (
    req: Request<{}, {}, { username: string; email: string; password: string }>,
    res: Response
  ) => {
    let { username, email, password } = req.body;

    username = username.trim().toLowerCase();
    email = email.trim().toLowerCase();
    password = password.trim();

    const ip = getClientIp(req);

    const userCache = await redisClient.get(REDIS_KEYS.usernameTemp(username));
    if (userCache && userCache === username) {
      throw new ApiError(409, "User already exists");
    }

    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ username }, { email }],
      },
    });

    if (existingUser) {
      throw new ApiError(409, "Username or email already exists");
    }

    const { otp, otpHash } = generateOTP();
    const { token, tokenHash } = generateToken();
    const passwordHash = await bcrypt.hash(password, 12);

    const userpayload = { username, email, password: passwordHash };
    const EXPIRES_IN = AUTH_OTP.EXPIRES_IN;
    await redisClient.set(
      REDIS_KEYS.userTemp(tokenHash),
      JSON.stringify(userpayload),
      { EX: EXPIRES_IN }
    );
    await redisClient.set(REDIS_KEYS.registerOtp(token), otpHash, {
      EX: EXPIRES_IN,
    });
    await redisClient.set(REDIS_KEYS.usernameTemp(username), username, {
      EX: EXPIRES_IN,
    });

    sendOtpEmail({ email, otp });

    await prisma.tokenHash.create({
      data: { token, tokenHash, userIp: ip },
    });

    return res.status(200).json({
      success: true,
      message: "OTP Sent Successfully",
      token,
    });
  }
);

export const registerStep2 = asyncHandler(
  async (
    req: Request<{}, {}, { token: string; otp: string }>,
    res: Response
  ) => {
    const { token, otp } = req.body;

    const ip = getClientIp(req);

    const tokenhash = await prisma.tokenHash.findFirst({
      where: { token: token },
    });

    if (!tokenhash) {
      throw new ApiError(400, "Invaild Token");
    }

    if (tokenhash.userIp !== ip) {
      throw new ApiError(400, "Invalid token or request");
    }

    const matchToken = verifyToken(token, tokenhash.tokenHash);
    if (!matchToken) {
      throw new ApiError(400, "Invaild Token");
    }

    const userData = await redisClient.get(
      REDIS_KEYS.userTemp(tokenhash.tokenHash)
    );
    if (!userData) {
      throw new ApiError(400, "Expired OTP");
    }

    const user = JSON.parse(userData);

    const otpHashed: string | null = await redisClient.get(
      REDIS_KEYS.registerOtp(token)
    );
    if (!otpHashed) {
      throw new ApiError(400, "Expired OTP");
    }

    const matchOTP = verifyOTP(otp, otpHashed);
    if (!matchOTP) {
      throw new ApiError(400, "Invaild OTP");
    }

    const newUser = await prisma.user.create({
      data: {
        username: user.username,
        email: user.email,
        password: user.password,
      }
    });

    delete (newUser as any).password;

    await redisClient.del(REDIS_KEYS.registerOtp(token));
    await redisClient.del(REDIS_KEYS.userTemp(tokenhash.tokenHash));

    await prisma.tokenHash.deleteMany({
      where: { token },
    });

    sendWelcomeEmail({email: user.email, name: user.username});

    if (newUser) {
      return res.status(201).json({
        success: true,
        message: "User Registered Successfully",
        user: newUser,
      });
    }
  }
);
