import { asyncHandler } from "../../utils/async-handler.js";
import { ApiError } from "../../utils/api-error.js";
import { prisma } from "../../config/prisma.config.ts";
import { redisClient, REDIS_KEYS } from "../../config/redis.config.ts";

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
