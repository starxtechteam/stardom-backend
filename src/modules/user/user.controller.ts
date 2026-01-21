import { asyncHandler } from "../../utils/async-handler.js";
import { ApiError } from "../../utils/api-error.js";
import { prisma } from "../../config/prisma.config.ts";
import { redisClient, REDIS_KEYS } from "../../config/redis.config.ts";
import { generateOTP, verifyOTP, generateToken } from "../../utils/core.ts";
import { changeEmailOtp } from "../../mails/user/changeEmailOTP.ts";
import { getClientIp, hashValue } from "../auth/auth.service.ts";
import bcrypt from "bcryptjs";
import { changePasswordOtp } from "../../mails/user/changePassword.ts";

export const userProfile = asyncHandler(async (req, res) => {
  const userId = req.session?.userId;

  if (!userId) {
    throw new ApiError(404, "User id not found");
  }

  const usercache = await redisClient.get(REDIS_KEYS.userdata(userId));
  if (usercache) {
    const user = await JSON.parse(usercache);
    return res.status(200).json({
      success: true,
      message: "Fetched user data",
      user: user,
    });
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      username: true,
      first_name: true,
      last_name: true,
      bio: true,
      avatarUrl: true,
      bannerUrl: true,
      isVerified: true,
      status: true,
      batch: true,
      isPremium: true,
      premiumEnds: true,
      createdAt: true,

      profile: {
        select: {
          gender: true,
          birthdate: true,
          location: true,
          websiteUrl: true,
          socialTwitter: true,
          socialFacebook: true,
          socialLinkedin: true,
          socialInstagram: true,
        },
      },
    },
  });

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  await redisClient.set(REDIS_KEYS.userdata(userId), JSON.stringify(user), {
    EX: 300,
  });

  return res.status(200).json({
    success: true,
    message: "Fetched user data",
    user: user,
  });
});

export const userProfileUpdate = asyncHandler(async (req, res) => {
  const {
    username,
    first_name,
    last_name,
    bio,
    avatarUrl,
    bannerUrl,
    gender,
    birthdate,
    location,
  } = req.body;

  const userId = req.session?.userId;

  if (!userId) {
    throw new ApiError(401, "Unauthorized");
  }

  if (username) {
    const existing = await prisma.user.findFirst({
      where: {
        username,
        NOT: { id: userId },
      },
      select: { id: true },
    });

    if (existing) {
      throw new ApiError(400, "Username already taken");
    }
  }

  const user = await prisma.$transaction(async (tx) => {
    await tx.user.update({
      where: { id: userId },
      data: {
        ...(username && { username }),
        ...(first_name && { first_name }),
        ...(last_name && { last_name }),
        ...(bio && { bio }),
        ...(avatarUrl && { avatarUrl }),
        ...(bannerUrl && { bannerUrl }),
      },
    });

    await tx.userProfile.upsert({
      where: { userId },
      update: {
        ...(gender && { gender }),
        ...(birthdate && { birthdate: new Date(birthdate) }),
        ...(location && { location }),
      },
      create: {
        userId,
        ...(gender && { gender }),
        ...(birthdate && { birthdate: new Date(birthdate) }),
        ...(location && { location }),
      },
    });

    const updatedUser = await tx.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        first_name: true,
        last_name: true,
        bio: true,
        avatarUrl: true,
        bannerUrl: true,
        profile: true,
      },
    });

    return updatedUser;
  });

  await redisClient.del(REDIS_KEYS.userdata(userId));

  res.status(200).json({
    success: true,
    message: "Profile updated successfully",
    data: user,
  });
});

export const updateSocialMedia = asyncHandler(async (req, res) => {
  const {
    websiteUrl,
    socialTwitter,
    socialFacebook,
    socialLinkedin,
    socialInstagram,
  } = req.body;

  const userId = req.session?.userId;

  if (
    !websiteUrl &&
    !socialTwitter &&
    !socialFacebook &&
    !socialLinkedin &&
    !socialInstagram
  ) {
    throw new ApiError(400, "No social media fields provided for update");
  }

  if (!userId) {
    throw new ApiError(401, "Unauthorized");
  }

  await prisma.userProfile.upsert({
    where: { userId },
    update: {
      ...(websiteUrl && { websiteUrl }),
      ...(socialTwitter && { socialTwitter }),
      ...(socialFacebook && { socialFacebook }),
      ...(socialLinkedin && { socialLinkedin }),
      ...(socialInstagram && { socialInstagram }),
    },
    create: {
      userId,
      ...(websiteUrl && { websiteUrl }),
      ...(socialTwitter && { socialTwitter }),
      ...(socialFacebook && { socialFacebook }),
      ...(socialLinkedin && { socialLinkedin }),
      ...(socialInstagram && { socialInstagram }),
    },
  });

  await redisClient.del(REDIS_KEYS.userdata(userId));

  return res.status(200).json({
    success: true,
    message: "User social media links updated successfully",
  });
});

export const changeMailStep1 = asyncHandler(async (req, res) => {
  const userId = req.session?.userId;
  let { email } = req.body;
  const ip = getClientIp(req);

  if (!email) throw new ApiError(400, "Invalid email");

  email = email.trim().toLowerCase();

  if (!userId) throw new ApiError(401, "Unauthorized");

  if (await redisClient.get(REDIS_KEYS.changeEmail(userId))) {
    throw new ApiError(429, "Email change already in progress");
  }

  const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [existingEmail, user, recentUpdate] = await Promise.all([
    prisma.user.findUnique({ where: { email } }),
    prisma.user.findUnique({ where: { id: userId } }),
    prisma.emailUpdatesHistory.findFirst({
      where: { userId, updatedAt: { gte: last24Hours } },
    }),
  ]);
  if (recentUpdate) {
    throw new ApiError(429, "You can only change email once every 24 hours");
  }

  if (existingEmail) throw new ApiError(409, "Someone use this email");
  if (!user) throw new ApiError(404, "User not found");
  if (user.status !== "active")
    throw new ApiError(403, `Account ${user.status}`);
  if (user.email === email)
    throw new ApiError(409, "New email cannot be same as current");

  const { otp, otpHash } = generateOTP();
  const { token, tokenHash } = generateToken();

  if (!(await changeEmailOtp({ email, otp }))) {
    throw new ApiError(500, "Failed to send OTP");
  }

  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

  await Promise.all([
    prisma.userOtp.create({
      data: {
        userId,
        purpose: "CHANGE_EMAIL_NEW",
        codeHash: otpHash,
        expiresAt,
      },
    }),

    prisma.tokenHash.create({
      data: {
        userId,
        token,
        tokenHash,
        userIp: ip,
        expiresAt,
      },
    }),

    redisClient.set(REDIS_KEYS.changeEmail(userId), email, { EX: 10 * 60 }),
  ]);

  return res.status(200).json({
    success: true,
    message: "OTP sent to new email",
    token,
  });
});

export const changeMailStep2 = asyncHandler(async (req, res) => {
  const { token, otp } = req.body;
  const userId = req.session?.userId;

  if (!token || !otp) throw new ApiError(400, "Token and OTP required");
  if (!userId) throw new ApiError(401, "Unauthorized");

  const checkToken = await prisma.tokenHash.findFirst({
    where: {
      userId,
      tokenHash: hashValue(token),
      expiresAt: { gte: new Date() },
    },
  });

  if (!checkToken) throw new ApiError(400, "Invalid or expired token");

  const checkOtp = await prisma.userOtp.findFirst({
    where: {
      userId,
      purpose: "CHANGE_EMAIL_NEW",
      expiresAt: { gte: new Date() },
    },
    orderBy: { createdAt: "desc" },
  });

  if (!checkOtp) {
    throw new ApiError(400, "Invalid or expired OTP");
  }

  if (!checkOtp || !verifyOTP(otp, checkOtp.codeHash)) {
    await prisma.userOtp.update({
      where: { id: checkOtp.id },
      data: { attempts: { increment: 1 } },
    });

    if (checkOtp.attempts >= 5) {
      await prisma.userOtp.delete({ where: { id: checkOtp.id } });
      throw new ApiError(429, "Too many invalid attempts");
    }

    throw new ApiError(400, "Invalid or expired OTP");
  }

  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user || user.status !== "active") {
    throw new ApiError(403, "Account not active");
  }

  const { otp: newOtp, otpHash: newOtpHash } = generateOTP();
  const { token: newToken, tokenHash: newTokenHash } = generateToken();

  if (!(await changeEmailOtp({ email: user.email, otp: newOtp }))) {
    throw new ApiError(500, "Failed to send OTP");
  }

  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  await Promise.all([
    prisma.userOtp.update({
      where: { id: checkOtp.id },
      data: {
        purpose: "CHANGE_EMAIL_OLD",
        codeHash: newOtpHash,
        expiresAt,
      },
    }),

    prisma.tokenHash.update({
      where: { id: checkToken.id },
      data: {
        tokenHash: newTokenHash,
        expiresAt,
      },
    }),
  ]);

  return res.status(200).json({
    success: true,
    message: "OTP sent to old email",
    token: newToken,
  });
});

export const changeMailStep3 = asyncHandler(async (req, res) => {
  const { token, otp } = req.body;
  const userId = req.session?.userId;

  if (!token || !otp) throw new ApiError(400, "Token and OTP required");
  if (!userId) throw new ApiError(401, "Unauthorized");

  const checkToken = await prisma.tokenHash.findFirst({
    where: {
      userId,
      tokenHash: hashValue(token),
      expiresAt: { gte: new Date() },
    },
  });

  if (!checkToken) throw new ApiError(400, "Invalid or expired token");

  const checkOtp = await prisma.userOtp.findFirst({
    where: {
      userId,
      purpose: "CHANGE_EMAIL_OLD",
      expiresAt: { gte: new Date() },
    },
    orderBy: { createdAt: "desc" },
  });

  if (!checkOtp) {
    throw new ApiError(400, "Invalid or expired OTP");
  }

  if (!checkOtp || !verifyOTP(otp, checkOtp.codeHash)) {
    await prisma.userOtp.update({
      where: { id: checkOtp.id },
      data: { attempts: { increment: 1 } },
    });

    if (checkOtp.attempts >= 5) {
      await prisma.userOtp.delete({ where: { id: checkOtp.id } });
      throw new ApiError(429, "Too many invalid attempts");
    }

    throw new ApiError(400, "Invalid or expired OTP");
  }

  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user || user.status !== "active") {
    throw new ApiError(403, "Account not active");
  }

  const newEmail = await redisClient.get(REDIS_KEYS.changeEmail(userId));
  if (!newEmail) throw new ApiError(400, "Email change session expired");

  await prisma.$transaction([
    prisma.emailUpdatesHistory.create({
      data: {
        userId,
        previousEmail: user.email,
        newEmail,
      },
    }),

    prisma.user.update({
      where: { id: userId },
      data: { email: newEmail },
    }),

    prisma.userOtp.delete({ where: { id: checkOtp.id } }),
    prisma.tokenHash.delete({ where: { id: checkToken.id } }),
  ]);

  await redisClient.del(REDIS_KEYS.changeEmail(userId));
  await redisClient.del(REDIS_KEYS.userdata(userId));

  return res.status(200).json({
    success: true,
    message: "Email updated successfully",
  });
});

export const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.session?.userId;

  if (!userId) throw new ApiError(401, "Unauthorized");

  if (!oldPassword || !newPassword) {
    throw new ApiError(400, "Old and new password are required");
  }

  if (oldPassword === newPassword) {
    throw new ApiError(400, "Choose a different password");
  }

  if (newPassword.length < 8) {
    throw new ApiError(400, "Password must be at least 8 characters");
  }

  const activeOtp = await redisClient.get(REDIS_KEYS.changePassword(userId));
  if (activeOtp) {
    throw new ApiError(429, "OTP already sent. Please wait.");
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) throw new ApiError(404, "User not found");
  if (user.status !== "active") {
    throw new ApiError(403, `Account is ${user.status}`);
  }

  const validOld = await bcrypt.compare(oldPassword, user.password);
  if (!validOld) {
    throw new ApiError(400, "Invalid credentials");
  }

  const twoFA = await prisma.userTotp.findFirst({
    where: { userId },
    select: { enabled: true },
  });

  const hashPassword = await bcrypt.hash(newPassword, 14);
  if (!twoFA?.enabled) {
    await prisma.user.update({
      where: { id: userId },
      data: { password: hashPassword },
    });

    return res.status(200).json({
      success: true,
      message: "Password has been changed",
    });
  }

  // 🛡 If 2FA is enabled → OTP challenge
  const { otp, otpHash } = generateOTP();
  const { token, tokenHash } = generateToken();

  if (!(await changePasswordOtp({ email: user.email, otp }))) {
    throw new ApiError(500, "Failed to send OTP");
  }

  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  const ip = getClientIp(req);

  await prisma.$transaction([
    prisma.userOtp.create({
      data: {
        userId,
        purpose: "CHANGE_PASSWORD",
        codeHash: otpHash,
        expiresAt,
      },
    }),

    prisma.tokenHash.create({
      data: {
        userId,
        token,
        tokenHash,
        userIp: ip,
        expiresAt,
      },
    }),
  ]);

  await redisClient.set(REDIS_KEYS.changePassword(userId), hashPassword, {
    EX: 5 * 60,
  });

  return res.status(200).json({
    success: true,
    message: "OTP sent successfully",
    token,
  });
});

export const changePasswordVerifyOTP = asyncHandler(async (req, res) => {
  const { token, otp } = req.body;
  const userId = req.session?.userId;

  if (!userId) throw new ApiError(401, "Unauthorized");
  if (!token || !otp) throw new ApiError(400, "Token and OTP are required");

  const newPasswordHash = await redisClient.get(
    REDIS_KEYS.changePassword(userId),
  );

  if (!newPasswordHash) {
    throw new ApiError(400, "Password change session expired");
  }

  const checkToken = await prisma.tokenHash.findFirst({
    where: {
      userId,
      tokenHash: hashValue(token),
      expiresAt: { gte: new Date() },
    },
  });

  if (!checkToken) {
    throw new ApiError(400, "Invalid or expired token");
  }

  const checkOtp = await prisma.userOtp.findFirst({
    where: {
      userId,
      purpose: "CHANGE_PASSWORD",
      expiresAt: { gte: new Date() },
    },
    orderBy: { createdAt: "desc" },
  });

  if (!checkOtp) {
    throw new ApiError(400, "Invalid or expired OTP");
  }

  if (!checkOtp || !verifyOTP(otp, checkOtp.codeHash)) {
    await prisma.userOtp.update({
      where: { id: checkOtp.id },
      data: { attempts: { increment: 1 } },
    });

    if (checkOtp.attempts >= 5) {
      await prisma.userOtp.delete({ where: { id: checkOtp.id } });
      throw new ApiError(429, "Too many invalid attempts");
    }

    throw new ApiError(400, "Invalid or expired OTP");
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) throw new ApiError(404, "User not found");
  if (user.status !== "active") {
    throw new ApiError(403, `Account is ${user.status}`);
  }

  await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: { password: newPasswordHash },
    }),

    prisma.userOtp.delete({ where: { id: checkOtp.id } }),

    prisma.tokenHash.delete({ where: { id: checkToken.id } }),
  ]);

  await redisClient.del(REDIS_KEYS.changePassword(userId));
  await redisClient.del(REDIS_KEYS.userdata(userId));

  return res.status(200).json({
    success: true,
    message: "Password has been changed",
  });
});
