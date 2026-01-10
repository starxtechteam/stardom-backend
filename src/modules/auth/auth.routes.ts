import express from "express";
import {
    registerOtp
} from "./auth.controller.js";
import {
    registerValidation 
} from "./auth.validation.ts";

const router = express.Router();

router.post("/register/otp", registerValidation, registerOtp);

export default router;