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

router.post('/presigned-url', presignedUrlValidation, generatePresignedUrl);
router.post('/', createPostValidation, createPost);

export default router;