import express from "express";
import {
    userProfile,
    userProfileUpdate,
    updateSocialMedia,
} from "./user.controller.ts";
import { verifyToken, roleAuth } from "../../middlewares/auth.ts";
import { updateProfileValidation, updateSocialValidation } from "./user.validation.ts";

const router = express.Router();

router.use(verifyToken, roleAuth("user"));
router.get("/profile", userProfile);
router.put("/profile", updateProfileValidation, userProfileUpdate);
router.put("/social-links", updateSocialValidation, updateSocialMedia);

export default router;