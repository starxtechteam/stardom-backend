import express from "express";
import {
    userProfile,
    userProfileUpdate,
} from "./user.controller.ts";
import { verifyToken, roleAuth } from "../../middlewares/auth.ts";
import { updateProfileValidation } from "./user.validation.ts";

const router = express.Router();

router.use(verifyToken, roleAuth("user"));
router.get("/profile", userProfile);
router.put("/profile", updateProfileValidation, userProfileUpdate);

export default router;