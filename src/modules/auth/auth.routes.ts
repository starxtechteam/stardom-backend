import express from "express";
import {
    registerStep1,
    registerStep2
} from "./auth.controller.js";
import {
    registerValidation,
    registerValidation2
} from "./auth.validation.ts"
import { authRateLimit } from "../../middlewares/ratelimit.ts"; 

const router = express.Router();

router.post("/register/otp", authRateLimit, registerValidation, registerStep1);
router.post("/register/verify/", registerValidation2, registerStep2);

export default router;