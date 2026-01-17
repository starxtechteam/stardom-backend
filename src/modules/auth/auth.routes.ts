import express from "express";
import {
  registerStep1,
  registerStep2,
  resendRegisterOTP,
  login,
  loginOTPVerify,
  enableOTPbasedLogin,
  verify2FAOTP,
  resendLoginOTP,
  refreshTokenHandler
} from "./auth.controller.js";
import {
  registerValidation,
  authVerify,
  loginValidate,
  tokenValidate,
  verify2FAValidate,
  refreshTokenValidate
} from "./auth.validation.ts";
import { authRateLimit } from "../../middlewares/ratelimit.ts";

import { verifyToken, roleAuth } from "../../middlewares/auth.ts";

const router = express.Router();

router.post("/register/otp", authRateLimit, registerValidation, registerStep1);
router.post("/register/verify", authVerify, registerStep2);
router.post("/register/otp/resend/:token", tokenValidate, resendRegisterOTP);
router.post("/login", loginValidate, login);
router.post("/login/otp-verify", authVerify, loginOTPVerify);
router.post("/login/otp/resend/:token", tokenValidate, resendLoginOTP);
router.post("/refresh-token", refreshTokenValidate, refreshTokenHandler);

router.use(verifyToken, roleAuth("user"))
router.post("/login/2fa/otp", enableOTPbasedLogin);
router.post("/login/2fa/verify/:token", tokenValidate, verify2FAValidate, verify2FAOTP);

export default router;
