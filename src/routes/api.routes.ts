import express from "express";
import authRoutes from "../modules/auth/auth.routes.js";
import userRoutes from "../modules/user/user.routes.ts";
const router = express.Router();

router.use('/auth', authRoutes);
router.use('/user', userRoutes);

export default router;