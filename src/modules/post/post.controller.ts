import { asyncHandler } from "../../utils/async-handler.js";
import { ApiError } from "../../utils/api-error.js";
import { prisma } from "../../config/prisma.config.ts";
import { redisClient, REDIS_KEYS } from "../../config/redis.config.ts";
import { bulkNotificationQueue } from "../../config/queue.ts";
import { generateMultipleUploadURLs, generateUploadURL } from "../../config/aws.ts";
import { getClientIp } from "../auth/auth.service.ts";
import { verifyFileKey, verifyFileKeys } from "./post.services.ts";

export const generatePresignedUrl = asyncHandler(async (req, res) => {
    const userId = req.session?.userId;
    const { mimeTypes, postType } = req.body;

    if (!userId) {
        throw new ApiError(401, "Unauthorized");
    }

    const ip = getClientIp(req);

    if (postType === "image") {
        if (!Array.isArray(mimeTypes) || mimeTypes.length === 0) {
            throw new ApiError(400, "mimeTypes must be a non-empty array");
        }

        const allowedMimeTypes = [
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif",
        ];

        // Validate all mime types
        const invalidType = mimeTypes.find(
            (type) => !allowedMimeTypes.includes(type)
        );

        if (invalidType) {
            throw new ApiError(400, `Unsupported file type: ${invalidType}`);
        }

        // Generate URLs
        const payload = await generateMultipleUploadURLs(mimeTypes);

        // Prepare bulk insert
        const uploadRecords = payload.map((item) => ({
            userId,
            mimeType: item.contentType,
            fileKey: item.key,
            uploadUrl: item.url,
            ipAddress: ip,
        }));

        await prisma.awsUploads.createMany({
            data: uploadRecords,
        });

        return res.status(200).json({
            success: true,
            data: payload,
        });
    }

    if (postType === "reel" || postType === "video") {

        if (!mimeTypes) {
            throw new ApiError(400, "mimeType is required");
        }

        const allowedMimeTypes = [
            "video/mp4",
            "video/webm",
        ];

        if (!allowedMimeTypes.includes(mimeTypes)) {
            throw new ApiError(400, "Unsupported file type");
        }

        const { url, key } = await generateUploadURL(mimeTypes);

        await prisma.awsUploads.create({
            data: {
                userId,
                mimeType: mimeTypes,
                fileKey: key,
                uploadUrl: url,
                ipAddress: ip,
            },
        });

        return res.status(200).json({
            success: true,
            message: "Presigned URL generated",
            uploadUrl: url,
            fileKey: key,
        });
    }

    throw new ApiError(400, "Invalid postType");
});

export const createPost = asyncHandler(async(req, res) => {
    const { postType, tags=[] } = req.body;
    const userId = req.session?.userId;

    if(!userId){
        throw new ApiError(400, "user id not found");
    }

    const user = await prisma.user.findUnique({
        where: { id: userId }
    });

    if(!user){
        throw new ApiError(400, "User not found");
    }

    if(user.status !== "active"){
        throw new ApiError(400, `Account is ${user.status}`);
    }

    const startOfToday = new Date();
    startOfToday.setHours(0, 0, 0, 0);
    const postLimit = await prisma.post.findMany({
        where: {
            userId,
            createdAt: {
                gte: startOfToday,
            },
        },
    });

    if(postLimit.length > 10){
        throw new ApiError(400, "Post limit reached of today")
    }

    const ip = getClientIp(req);

    let post = null;
    if(postType === "text"){
        const {content} = req.body;
        if(!content){
            throw new ApiError(400, "content is required");
        }

        post = await prisma.post.create({
            data: {
                userId,
                content,
                postType,
            }
        });

    } else if (postType === "image"){
        let { content, images=[] } = req.body;
        if(images.length === 0){
            throw new ApiError(400, "images is required");
        }

        images = [...new Set(images)];

        // verify images urls
        const isVerified = await verifyFileKeys(userId, images, ip);
        if(!isVerified){
            throw new ApiError(400, "Invaild Images");
        }

        post = await prisma.post.create({
            data: {
                userId,
                content,
                postType,
                images
            }
        });

        await prisma.awsUploads.updateMany({
            where: {
                fileKey: {
                    in: images
                },
                userId,
                ipAddress: ip
            },
            data: {
                status: "USED"
            }
        });
    } else if(postType === "video"){
        const {content, mediaUrl, thumbnailUrl, durationSec} = req.body;

        const isVerified = await verifyFileKey(userId, mediaUrl, ip);
        if(!isVerified){
            throw new ApiError(400, "Invaild Video")
        }

        post = await prisma.post.create({
            data: {
                userId,
                content,
                postType,
                mediaUrl,
                thumbnailUrl,
                durationSec
            }
        });

        await prisma.awsUploads.updateMany({
            where: {
                fileKey: mediaUrl,
                userId,
                ipAddress: ip
            },
            data: {
                status: "USED"
            }
        });
    } else if(postType === "reel") {
        const {content, mediaUrl, thumbnailUrl, durationSec, musicName, musicUrl} = req.body;

        const isVerified = await verifyFileKey(userId, mediaUrl, ip);
        if(!isVerified){
            throw new ApiError(500, "Invaild reel")
        }

        post = await prisma.post.create({
            data: {
                userId,
                content,
                postType,
                mediaUrl,
                thumbnailUrl,
                durationSec
            }
        });

        await prisma.reel.create({
            data: {
                postId: post.id,
                musicName,
                musicUrl
            }
        });

        await prisma.awsUploads.updateMany({
            where: {
                fileKey: mediaUrl,
                userId,
                ipAddress: ip
            },
            data: {
                status: "USED"
            }
        });
    }

    if(!post){
        throw new ApiError(400, "Something went wrong")
    }

    await prisma.$transaction(async (tx) => {
        await tx.hashtag.createMany({
            data: tags.map((tag: string) => ({
                tag,
                createdBy: userId,
            })),
            skipDuplicates: true,
        });

        const savedTags = await tx.hashtag.findMany({
            where: {
                tag: { in: tags },
                createdBy: userId,
            },
        });

        await tx.postHashtag.createMany({
            data: savedTags.map((tag) => ({
                postId: post.id,
                hashtagId: tag.id,
            })),
            skipDuplicates: true,
        });
    });

    // notify to all followers
    await bulkNotificationQueue.add("Post-Notification", {
        postId: post.id,
        userId: userId
    });

    return res.status(200).json({
        success: true,
        message: "New post created.",
        post: post
    });
});
