import express from "express";
import {
    userProfile
} from "./user.controller.ts";
import { verifyToken, roleAuth } from "../../middlewares/auth.ts";

const router = express.Router();

router.use(verifyToken, roleAuth("user"));
router.get("/profile", userProfile);

export default router;