import type { Request, Response } from "express";
import { asyncHandler } from "../../utils/async-handler.js";
import { ApiError } from "../../utils/api-error.js";
import { prisma } from "../../config/prisma.config.ts";
import { redisClient, REDIS_KEYS } from "../../config/redis.config.ts";
import bcrypt from "bcryptjs";
import {
  AUTH_OTP,
  MAXIMUM_LOGGEDIN_DEVICE,
} from "../../constants/auth.constants.ts";
import { sendOtpEmail } from "../../mails/auth/registerOtp.mails.ts";
import { sendWelcomeEmail } from "../../mails/user/welcome.mails.ts";
import { sendLoginOtp } from "../../mails/auth/loginOtp.mails.ts";
import { sendEnable2FAOtpEmail } from "../../mails/user/sendEnable2FAOtpEmail.ts";
import { sendEnable2FAEmail } from "../../mails/user/sendEnable2FAEmail.ts";
import {
  generateOTP,
  verifyOTP,
  generateToken,
  verifyToken,
} from "../../utils/core.ts";
import {
  getClientIp,
  getDeviceInfo,
  saveLoginAttempts,
  verifyUserLoginAttempts,
  signAccessToken,
  signRefreshToken,
  hashValue,
  invalidateOtp,
  actualLogin,
} from "./auth.service.ts";
import type { LoginAttempts } from "../../types/auth.types.ts";

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

    if (!sendOtpEmail({ email, otp })) {
      throw new ApiError(400, "Something went wrong. Please try again later");
    }

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

    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    const tokenhash = await prisma.tokenHash.findFirst({
      where: {
        AND: [{ token: token }, { createdAt: { gte: fiveMinutesAgo } }],
      },
    });

    if (!tokenhash) {
      throw new ApiError(400, "OTP expired or invalid");
    }

    if (tokenhash.userIp !== ip) {
      throw new ApiError(400, "OTP expired or invalid");
    }

    const matchToken = verifyToken(token, tokenhash.tokenHash);
    if (!matchToken) {
      throw new ApiError(400, "OTP expired or invalid");
    }

    const userData = await redisClient.get(
      REDIS_KEYS.userTemp(tokenhash.tokenHash)
    );
    if (!userData) {
      throw new ApiError(400, "OTP expired or invalid");
    }

    const user = JSON.parse(userData);

    const otpHashed: string | null = await redisClient.get(
      REDIS_KEYS.registerOtp(token)
    );
    if (!otpHashed) {
      throw new ApiError(400, "OTP expired or invalid");
    }

    const matchOTP = verifyOTP(otp, otpHashed);
    if (!matchOTP) {
      throw new ApiError(400, "OTP expired or invalid");
    }

    const newUser = await prisma.user.create({
      data: {
        username: user.username,
        email: user.email,
        password: user.password,
      },
    });

    delete (newUser as any).password;

    await redisClient.del(REDIS_KEYS.registerOtp(token));
    await redisClient.del(REDIS_KEYS.userTemp(tokenhash.tokenHash));

    await prisma.tokenHash.deleteMany({
      where: { token },
    });

    sendWelcomeEmail({ email: user.email, name: user.username });

    if (newUser) {
      return res.status(201).json({
        success: true,
        message: "User Registered Successfully",
        user: newUser,
      });
    }
  }
);

export const resendRegisterOTP = asyncHandler(async (req, res) => {
  const { token } = req.params;

  const resendAttempt = await redisClient.incr(
    REDIS_KEYS.resendRegisterOTP(token)
  );
  if (resendAttempt >= 5) {
    throw new ApiError(429, "Too many requests");
  }

  const ip = getClientIp(req);

  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
  const tokenhash = await prisma.tokenHash.findFirst({
    where: {
      AND: [{ token: token }, { createdAt: { gte: fiveMinutesAgo } }],
    },
  });

  if (!tokenhash) {
    throw new ApiError(400, "OTP expired or invalid");
  }

  if (tokenhash.userIp !== ip) {
    throw new ApiError(403, "Inavild Request");
  }

  const matchToken = verifyToken(token, tokenhash.tokenHash);
  if (!matchToken) {
    throw new ApiError(400, "OTP expired or invalid");
  }

  const userData = await redisClient.get(
    REDIS_KEYS.userTemp(tokenhash.tokenHash)
  );
  if (!userData) {
    throw new ApiError(400, "OTP expired or invalid");
  }

  const otpHashed: string | null = await redisClient.get(
    REDIS_KEYS.registerOtp(token)
  );
  if (!otpHashed) {
    throw new ApiError(400, "OTP expired or invalid");
  }

  const user = await JSON.parse(userData);
  const { otp, otpHash } = generateOTP();
  const EXPIRES_IN = AUTH_OTP.EXPIRES_IN;
  await redisClient.set(REDIS_KEYS.registerOtp(token), otpHash, {
    EX: EXPIRES_IN,
  });
  await redisClient.set(REDIS_KEYS.userTemp(tokenhash.tokenHash), userData, {
    EX: EXPIRES_IN,
  });
  await redisClient.set(REDIS_KEYS.usernameTemp(user.username), user.username, {
    EX: EXPIRES_IN,
  });

  if (!(await sendOtpEmail({ email: user.email, otp }))) {
    throw new ApiError(400, "Something went wrong. Please try again later");
  }

  res.status(200).json({
    success: true,
    message: "OTP Resend Successfully",
  });
});

export const login = asyncHandler(
  async (
    req: Request<{}, {}, { usernameOrEmail: string; password: string }>,
    res: Response
  ) => {
    let { usernameOrEmail, password } = req.body;

    usernameOrEmail = usernameOrEmail.trim().toLowerCase();
    password = password.trim();

    const lastCache = await redisClient.get(
      REDIS_KEYS.identifierHash(hashValue(usernameOrEmail))
    );
    if (lastCache) {
      throw new ApiError(400, "Please try again later.");
    }

    const ip = getClientIp(req);
    const device = getDeviceInfo(req);

    const attempt: LoginAttempts = {
      identifier: usernameOrEmail,
      ipAddress: ip,
      deviceName: device.deviceName,
      deviceType: device.deviceType,
      os: device.os,
      browser: device.browser,
      success: false,
      message: "Invalid credentials",
    };

    if (!(await verifyUserLoginAttempts(attempt))) {
      throw new ApiError(429, "Too many requests");
    }

    const user = await prisma.user.findFirst({
      where: {
        OR: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
      },
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      await saveLoginAttempts(attempt);
      throw new ApiError(403, "Invalid credentials");
    }

    if (user.status !== "active") {
      await saveLoginAttempts({ ...attempt, message: user.status });
      throw new ApiError(403, `Account ${user.status}`);
    }

    const session = await prisma.userSession.findMany({
      where: {
        userId: user.id,
        createdAt: { gte: new Date(Date.now() - 5 * 60 * 1000) },
      },
    });

    if (session && session.length > MAXIMUM_LOGGEDIN_DEVICE) {
      await saveLoginAttempts({
        ...attempt,
        message: "Logged in too many device",
      });
      throw new ApiError(429, "Logged in too many device");
    }

    const Enabled2FA = await prisma.userTotp.findFirst({
      where: { userId: user.id },
    });

    if (!Enabled2FA || !Enabled2FA.enabled) {
      const { accessToken, refreshToken } = await actualLogin(
        user.id,
        usernameOrEmail,
        device,
        ip
      );

      return res.status(200).json({
        success: true,
        accessToken: accessToken,
        refreshToken: refreshToken,
      });
    }

    const { otp, otpHash } = generateOTP();
    const { token, tokenHash } = generateToken();

    await prisma.tokenHash.create({
      data: { token, tokenHash, userIp: ip },
    });

    await redisClient.set(REDIS_KEYS.loginOtp(tokenHash), otpHash, {
      EX: AUTH_OTP.EXPIRES_IN,
    });

    await redisClient.set(REDIS_KEYS.identifier(tokenHash), usernameOrEmail, {
      EX: AUTH_OTP.EXPIRES_IN,
    });

    await redisClient.set(REDIS_KEYS.isotp(tokenHash), "0", {
      EX: AUTH_OTP.EXPIRES_IN,
    });

    if (!(await sendLoginOtp({ email: user.email, otp }))) {
      throw new ApiError(400, "Something went wrong. Please try again later");
    }

    await redisClient.set(
      REDIS_KEYS.identifierHash(hashValue(usernameOrEmail)),
      "1",
      { EX: AUTH_OTP.EXPIRES_IN }
    );
    await saveLoginAttempts({ ...attempt, success: true, message: "OTP sent" });

    res.status(200).json({
      success: true,
      token,
    });
  }
);

export const loginOTPVerify = asyncHandler(async (req, res) => {
  const { token, otp } = req.body;

  const ip = getClientIp(req);
  const device = getDeviceInfo(req);

  const tokenHash = hashValue(token);

  const dbToken = await prisma.tokenHash.findFirst({
    where: {
      tokenHash,
      createdAt: { gte: new Date(Date.now() - 5 * 60 * 1000) },
    },
  });

  if (!dbToken || dbToken.userIp !== ip) {
    throw new ApiError(400, "OTP expired or invalid");
  }

  const verifyKey = REDIS_KEYS.otpVerify(tokenHash);
  const attempts = await redisClient.incr(verifyKey);

  if (attempts === 1) {
    await redisClient.expire(verifyKey, AUTH_OTP.EXPIRES_IN);
  }

  if (attempts > 5) {
    await invalidateOtp(tokenHash);
    throw new ApiError(429, "OTP attempts exceeded");
  }

  const storedOtpHash = await redisClient.get(REDIS_KEYS.loginOtp(tokenHash));

  if (!storedOtpHash || !verifyOTP(otp, storedOtpHash)) {
    throw new ApiError(400, "Wrong OTP");
  }

  const identifier = await redisClient.get(REDIS_KEYS.identifier(tokenHash));

  if (!identifier) {
    throw new ApiError(400, "OTP expired");
  }

  const user = await prisma.user.findFirst({
    where: {
      OR: [{ username: identifier }, { email: identifier }],
    },
  });

  if (!user || user.status !== "active") {
    throw new ApiError(403, "Inactive or invalid user");
  }

  await Promise.all([
    prisma.tokenHash.delete({ where: { id: dbToken.id } }),
    invalidateOtp(tokenHash),
  ]);

  const { accessToken, refreshToken } = await actualLogin(
    user.id,
    identifier,
    device,
    ip
  );

  res.status(200).json({
    success: true,
    accessToken: accessToken,
    refreshToken: refreshToken,
  });
});

export const resendLoginOTP = asyncHandler(async (req, res) => {
  const { token } = req.params;
  const ip = getClientIp(req);

  const tokenHash = hashValue(token);
  const dbToken = await prisma.tokenHash.findFirst({
    where: {
      tokenHash,
      createdAt: { gte: new Date(Date.now() - 10 * 60 * 1000) },
    },
  });
  if (!dbToken) {
    throw new ApiError(400, "Invaild token");
  }
  if (dbToken.userIp !== ip) {
    throw new ApiError(403, "Invaild request");
  }

  const storedOtpHash = await redisClient.get(REDIS_KEYS.loginOtp(tokenHash));
  if (!storedOtpHash) {
    throw new ApiError(400, "Invaild token");
  }

  const { otp, otpHash } = generateOTP();
  await redisClient.set(REDIS_KEYS.loginOtp(tokenHash), otpHash, {
    EX: AUTH_OTP.EXPIRES_IN,
  });

  const identifier = await redisClient.get(REDIS_KEYS.identifier(tokenHash));
  if (!identifier) {
    throw new ApiError(400, "OTP expired");
  }

  const user = await prisma.user.findFirst({
    where: {
      OR: [{ username: identifier }, { email: identifier }],
    },
  });

  if (!user || user.status !== "active") {
    throw new ApiError(403, "Inactive or invalid user");
  }

  if (!(await sendLoginOtp({ email: user.email, otp }))) {
    throw new ApiError(400, "Something went wrong. Please try again later");
  }

  return res.status(200).json({
    success: true,
    messgae:"OTP Resend Successfully"
  })
});

export const enableOTPbasedLogin = asyncHandler(async (req, res) => {
  const { id: userId } = req.params;

  if (!userId) {
    throw new ApiError(400, "Invalid userId");
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  if (user.status !== "active") {
    throw new ApiError(403, `Account ${user.status}`);
  }

  const alreadyEnabled = await prisma.userTotp.findFirst({
    where: { userId, enabled: true },
  });

  if (alreadyEnabled) {
    throw new ApiError(409, "OTP-based login already enabled");
  }

  const { otp, otpHash } = generateOTP();
  const { token, tokenHash } = generateToken();

  const ip = getClientIp(req);

  await prisma.$transaction([
    prisma.userTotp.upsert({
      where: { userId },
      update: { secret: tokenHash },
      create: {
        userId,
        secret: tokenHash,
        enabled: false,
      },
    }),

    prisma.userOtp.create({
      data: {
        userId,
        purpose: "ENABLE_2FA",
        codeHash: otpHash,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      },
    }),

    prisma.tokenHash.create({
      data: {
        token: token,
        tokenHash,
        userIp: ip,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      },
    }),
  ]);

  const emailSent = await sendEnable2FAOtpEmail({
    email: user.email,
    otp,
  });

  if (!emailSent) {
    throw new ApiError(500, "Failed to send OTP email");
  }

  res.status(200).json({
    success: true,
    message: "OTP sent successfully",
    token,
  });
});

export const verify2FAOTP = asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { otp } = req.body;

  if (!token || !otp) {
    throw new ApiError(400, "Token and OTP are required");
  }

  const ip = getClientIp(req);
  const device = getDeviceInfo(req);

  const tokenEntry = await prisma.tokenHash.findFirst({
    where: {
      tokenHash: hashValue(token),
      userIp: ip,
      expiresAt: { gt: new Date() },
    },
  });

  if (!tokenEntry) {
    throw new ApiError(400, "Invalid or expired token");
  }

  const userOTP = await prisma.userOtp.findFirst({
    where: {
      purpose: "ENABLE_2FA",
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: "desc" },
  });

  if (!userOTP) {
    throw new ApiError(400, "Invalid or expired OTP");
  }

  const isValidOtp = verifyOTP(otp, userOTP.codeHash);

  if (!isValidOtp) {
    throw new ApiError(400, "Invalid or expired OTP");
  }

  await prisma.$transaction([
    prisma.userTotp.update({
      where: { userId: userOTP.userId },
      data: {
        enabled: true,
        verifiedAt: new Date(),
      },
    }),

    prisma.userOtp.deleteMany({
      where: { userId: userOTP.userId },
    }),

    prisma.tokenHash.deleteMany({
      where: { tokenHash: tokenEntry.tokenHash },
    }),
  ]);

  await sendEnable2FAEmail({
    email: (await prisma.user.findUnique({ where: { id: userOTP.userId } }))!
      .email,
    device: device.deviceName || device.deviceType,
  });

  res.status(200).json({
    success: true,
    message: "OTP-based login enabled successfully",
  });
});
