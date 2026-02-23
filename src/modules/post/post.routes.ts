import express from "express";
import {
    createPost,
    generatePresignedUrl
} from "./post.controller.ts";
import {
    createPostValidation,
    presignedUrlValidation
} from "./post.validation.ts";
import { createVerifyToken } from "../../middlewares/auth.ts";

const router = express.Router();
router.use(createVerifyToken("user"));

/**
 * @swagger
 * /api/v1/post/presigned-url:
 *   post:
 *     summary: Generate presigned upload URL(s) for post media
 *     description: |
 *       Generate AWS S3 presigned URL(s) before creating image/video/reel posts.
 *
 *       - For `image`, send `mimeTypes` as an array of image MIME types.
 *       - For `video` or `reel`, send `mimeTypes` as a single video MIME type string.
 *     tags: [Post]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - postType
 *               - mimeTypes
 *             properties:
 *               postType:
 *                 type: string
 *                 enum: [image, video, reel]
 *                 example: image
 *               mimeTypes:
 *                 oneOf:
 *                   - type: string
 *                     enum: [video/mp4, video/webm]
 *                     example: video/mp4
 *                   - type: array
 *                     items:
 *                       type: string
 *                       enum: [image/jpeg, image/png, image/webp, image/gif]
 *                     minItems: 1
 *                     example: [image/jpeg, image/png]
 *     responses:
 *       200:
 *         description: Presigned URL(s) generated successfully
 *       400:
 *         description: Invalid postType or mimeTypes
 *       401:
 *         description: Unauthorized - missing or invalid token
 */
router.post('/presigned-url', presignedUrlValidation, generatePresignedUrl);

/**
 * @swagger
 * /api/v1/post/:
 *   post:
 *     summary: Create a post
 *     description: |
 *       Create a post for the authenticated user.
 *
 *       Supported post types:
 *       - `text`: content only
 *       - `image`: content + uploaded image file keys
 *       - `video`: content + uploaded video file key
 *       - `reel`: content + uploaded video file key + optional music metadata
 *     tags: [Post]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             oneOf:
 *               - type: object
 *                 required:
 *                   - postType
 *                   - content
 *                 properties:
 *                   postType:
 *                     type: string
 *                     enum: [text]
 *                   content:
 *                     type: string
 *                     maxLength: 1000
 *                   tags:
 *                     type: array
 *                     items:
 *                       type: string
 *                     maxItems: 20
 *               - type: object
 *                 required:
 *                   - postType
 *                   - images
 *                 properties:
 *                   postType:
 *                     type: string
 *                     enum: [image]
 *                   content:
 *                     type: string
 *                     maxLength: 1000
 *                   images:
 *                     type: array
 *                     items:
 *                       type: string
 *                     minItems: 1
 *                     maxItems: 10
 *                   tags:
 *                     type: array
 *                     items:
 *                       type: string
 *                     maxItems: 20
 *               - type: object
 *                 required:
 *                   - postType
 *                   - mediaUrl
 *                   - durationSec
 *                 properties:
 *                   postType:
 *                     type: string
 *                     enum: [video]
 *                   content:
 *                     type: string
 *                     maxLength: 1000
 *                   mediaUrl:
 *                     type: string
 *                   thumbnailUrl:
 *                     type: string
 *                   durationSec:
 *                     type: number
 *                     minimum: 0
 *                   tags:
 *                     type: array
 *                     items:
 *                       type: string
 *                     maxItems: 20
 *               - type: object
 *                 required:
 *                   - postType
 *                   - mediaUrl
 *                   - durationSec
 *                   - musicName
 *                   - musicUrl
 *                 properties:
 *                   postType:
 *                     type: string
 *                     enum: [reel]
 *                   content:
 *                     type: string
 *                     maxLength: 1000
 *                   mediaUrl:
 *                     type: string
 *                   thumbnailUrl:
 *                     type: string
 *                   durationSec:
 *                     type: number
 *                     minimum: 0
 *                   musicName:
 *                     type: string
 *                   musicUrl:
 *                     type: string
 *                     format: uri
 *                   tags:
 *                     type: array
 *                     items:
 *                       type: string
 *                     maxItems: 20
 *     responses:
 *       200:
 *         description: Post created successfully
 *       400:
 *         description: Invalid input, file verification failed, or account/post-limit restriction
 *       401:
 *         description: Unauthorized - missing or invalid token
 */
router.post('/', createPostValidation, createPost);

export default router;