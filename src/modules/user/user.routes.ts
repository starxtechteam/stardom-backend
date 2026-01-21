import express from "express";
import {
  userProfile,
  userProfileUpdate,
  updateSocialMedia,
  changeMailStep1,
  changeMailStep2,
  changeMailStep3,
  changePassword,
  changePasswordVerifyOTP
} from "./user.controller.ts";
import { verifyToken, roleAuth } from "../../middlewares/auth.ts";
import {
  updateProfileValidation,
  updateSocialValidation,
  changeEmailValidation,
  changeEmailValidation2,
  changePasswordValidation,
  changePasswordVerify
} from "./user.validation.ts";

const router = express.Router();

router.use(verifyToken, roleAuth("user"));
router.get("/profile", userProfile);
router.put("/profile", updateProfileValidation, userProfileUpdate);
router.put("/social-links", updateSocialValidation, updateSocialMedia);
router.post("/change-email", changeEmailValidation, changeMailStep1);
router.post("/change-email/verify", changeEmailValidation2, changeMailStep2);
router.post("/change-email/update", changeEmailValidation2, changeMailStep3);
router.post("/change-password", changePasswordValidation, changePassword);
router.post("/change-password/verify", changePasswordVerify, changePasswordVerifyOTP);

export default router;