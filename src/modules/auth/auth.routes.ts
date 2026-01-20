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
  refreshTokenHandler,
  resetPasswordStep1,
  resetPasswordStep2,
  resetPasswordStep3
} from "./auth.controller.js";
import {
  registerValidation,
  authVerify,
  loginValidate,
  tokenValidate,
  verify2FAValidate,
  refreshTokenValidate,
  resetPasswordValidate1,
  resetPasswordValidate2,
  resetPasswordValidate3
} from "./auth.validation.ts";
import { authRateLimit } from "../../middlewares/ratelimit.ts";

import { verifyToken, roleAuth } from "../../middlewares/auth.ts";

const router = express.Router();

router.post("/register/otp", authRateLimit, registerValidation, registerStep1);
router.post("/register/verify", authVerify, registerStep2);
router.post("/register/otp/resend/:token", tokenValidate, resendRegisterOTP);
router.post("/login", authRateLimit, loginValidate, login);
router.post("/login/otp-verify", authVerify, loginOTPVerify);
router.post("/login/otp/resend/:token", tokenValidate, resendLoginOTP);
router.post("/refresh-token", authRateLimit, refreshTokenValidate, refreshTokenHandler);
router.post("/reset-password/request", authRateLimit, resetPasswordValidate1, resetPasswordStep1);
router.post("/reset-password/verify", resetPasswordValidate2, resetPasswordStep2);
router.post("/reset-password", resetPasswordValidate3, resetPasswordStep3);

router.use(verifyToken, roleAuth("user"));
router.post("/login/2fa/otp", enableOTPbasedLogin);
router.post("/login/2fa/verify/:token", tokenValidate, verify2FAValidate, verify2FAOTP);

export default router;