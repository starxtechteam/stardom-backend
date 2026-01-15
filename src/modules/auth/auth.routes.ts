import express from "express";
import {
  registerStep1,
  registerStep2,
  loginStep1,
  loginStep2,
} from "./auth.controller.js";
import {
  registerValidation,
  authVerify,
  loginValidate,
} from "./auth.validation.ts";
import { authRateLimit } from "../../middlewares/ratelimit.ts";

const router = express.Router();

router.post("/register/otp", authRateLimit, registerValidation, registerStep1);
router.post("/register/verify", authVerify, registerStep2);
router.post("/login/otp", loginValidate, loginStep1);
router.post("/login/verify", authVerify, loginStep2);

export default router;
