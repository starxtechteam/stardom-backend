import express from "express";
import {
    createPost,
    deletePost,
    rePost,
    generatePresignedUrl,
    updatePost,
    bookmarkPost,
    likePost,
    dislikePost,
    commentOnPost,
    editComment,
    deleteComment,
    replyOnComment,
} from "./post.controller.ts";
import {
    createPostValidation,
    presignedUrlValidation,
    postIdValidation,
    repostValidation,
    updateValidation,
    commentValidation,
    deleteCommentValidation,
    commentReplyValidation,
    editCommentValidation,
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

/**
 * @swagger
 * /api/v1/post/update:
 *   put:
 *     summary: Update a post
 *     description: Update content, visibility, or status of a post owned by the authenticated user.
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
 *               - postId
 *               - visibility
 *               - status
 *             properties:
 *               postId:
 *                 type: string
 *                 format: uuid
 *               content:
 *                 type: string
 *                 maxLength: 1000
 *               visibility:
 *                 type: string
 *                 enum: [public, private, followers]
 *               status:
 *                 type: string
 *                 enum: [active, archived, draft]
 *     responses:
 *       200:
 *         description: Post updated successfully
 *       400:
 *         description: Invalid request or post not found
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Forbidden - post does not belong to authenticated user
 */
router.put('/update', updateValidation, updatePost);

/**
 * @swagger
 * /api/v1/post/{postId}:
 *   delete:
 *     summary: Delete a post
 *     description: Delete a post owned by the authenticated user.
 *     tags: [Post]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: postId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Post deleted successfully
 *       400:
 *         description: Invalid post id or bad request
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Forbidden - post does not belong to authenticated user
 */
router.delete("/:postId", postIdValidation, deletePost);

/**
 * @swagger
 * /api/v1/post/repost:
 *   post:
 *     summary: Repost a post
 *     description: Create a repost of an existing post for the authenticated user.
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
 *               - postId
 *               - visibility
 *             properties:
 *               postId:
 *                 type: string
 *                 format: uuid
 *               content:
 *                 type: string
 *                 maxLength: 1000
 *               visibility:
 *                 type: string
 *                 enum: [public, private, followers]
 *     responses:
 *       200:
 *         description: Post reposted successfully
 *       400:
 *         description: Invalid request, repost limit reached, or duplicate repost
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Forbidden - cannot repost this post
 *       404:
 *         description: Post not found
 */
router.post('/repost', repostValidation, rePost);

/**
 * @swagger
 * /api/v1/post/bookmark/{postId}:
 *   post:
 *     summary: Bookmark a post
 *     description: Add a post to the authenticated user's bookmarks.
 *     tags: [Post]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: postId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Post bookmarked successfully
 *       400:
 *         description: Invalid request, post inactive, or already bookmarked
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Forbidden - account is not active
 *       404:
 *         description: User or post not found
 */
router.post('/bookmark/:postId', postIdValidation, bookmarkPost);

/**
 * @swagger
 * /api/v1/post/like/{postId}:
 *   patch:
 *     summary: Like a post
 *     description: Add a like to an active post for the authenticated user.
 *     tags: [Post]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: postId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Post liked successfully
 *       400:
 *         description: Invalid request, post inactive, or already liked
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Forbidden - account is not active
 *       404:
 *         description: User or post not found
 */
router.patch('/like/:postId', postIdValidation, likePost);

/**
 * @swagger
 * /api/v1/post/dislike/{postId}:
 *   patch:
 *     summary: Dislike a post
 *     description: Remove the authenticated user's like from an active post.
 *     tags: [Post]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: postId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Post disliked successfully
 *       400:
 *         description: Invalid request or post inactive
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Forbidden - account is not active
 *       404:
 *         description: User or post not found
 */
router.patch('/dislike/:postId', postIdValidation, dislikePost);

/**
 * @swagger
 * /api/v1/post/comment:
 *   post:
 *     summary: Comment on a post
 *     description: Add a comment to an active post as the authenticated user, with optional image attachment.
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
 *               - postId
 *               - content
 *             properties:
 *               postId:
 *                 type: string
 *                 format: uuid
 *               content:
 *                 type: string
 *                 maxLength: 1000
 *               imageKey:
 *                 type: string
 *                 maxLength: 500
 *                 description: Optional uploaded image file key
 *     responses:
 *       200:
 *         description: Comment created successfully
 *       400:
 *         description: Invalid request, inactive post, invalid image key, or comment limit reached
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Forbidden - account is not active
 *       404:
 *         description: User or post not found
 */
router.post('/comment', commentValidation, commentOnPost);

/**
 * @swagger
 * /api/v1/post/comment:
 *   put:
 *     summary: Edit a comment
 *     description: Update the authenticated user's existing comment on an active post.
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
 *               - commentId
 *               - content
 *             properties:
 *               commentId:
 *                 type: string
 *                 format: uuid
 *               content:
 *                 type: string
 *                 maxLength: 1000
 *     responses:
 *       200:
 *         description: Comment updated successfully
 *       400:
 *         description: Invalid request or post is not active
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       403:
 *         description: Forbidden - account is not active or comment does not belong to user
 *       404:
 *         description: User or comment not found
 */
router.put('/comment', editCommentValidation, editComment);

/**
 * @swagger
 * /api/v1/post/comment/reply:
 *   post:
 *     summary: Reply to a comment
 *     description: Add a reply to an existing comment on an active post.
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
 *               - commentId
 *               - content
 *             properties:
 *               commentId:
 *                 type: string
 *                 format: uuid
 *               content:
 *                 type: string
 *                 maxLength: 1000
 *     responses:
 *       201:
 *         description: Reply added successfully
 *       400:
 *         description: Missing/invalid input or inactive post/account
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       404:
 *         description: Comment not found
 */
router.post("/comment/reply", commentReplyValidation, replyOnComment);

/**
 * @swagger
 * /api/v1/post/comment/{postId}/{commentId}:
 *   delete:
 *     summary: Delete a comment
 *     description: Delete the authenticated user's comment from an active post.
 *     tags: [Post]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: postId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *       - in: path
 *         name: commentId
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Comment deleted successfully
 *       400:
 *         description: Invalid request or post/account is not active
 *       401:
 *         description: Unauthorized - missing or invalid token
 *       404:
 *         description: Post not found or invalid comment id
 */
router.delete('/comment/:postId/:commentId', deleteCommentValidation, deleteComment);

export default router;