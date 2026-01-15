import { z } from 'zod';
import { validationInput } from  "../../utils/validation.ts";

const usernameSchema = z.object({
  username: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^[a-z][a-z0-9._]{2,29}$/),
});

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const registerSchema = usernameSchema.extend({
    email: z.email('Email is required').toLowerCase().trim(),
    password: z
      .string("Password is required")
      .min(8, "Password must be at least 8 characters long")
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
      ),
    confirmPassword: z
      .string("Password confirmation is required")
      .min(1, "Password confirmation is required"),
}).refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
});

const verifyAuthSchema = z.object({
  token: z.string('Token is required'),
  otp: z.string('OTP is required').min(6, 'Invaild OTP').max(6, 'Invaild OTP')
})

const userLoginSchema = z.object({
  usernameOrEmail: z
    .string()
    .min(1, "Email or Username is required")
    .trim()
    .refine(
      (val) => emailRegex.test(val) || /^[a-z][a-z0-9._]{2,29}$/.test(val),
      "Must be a valid email or username"
    ),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(50, "Password too long"),
});

export const registerValidation = validationInput(registerSchema);
export const authVerify = validationInput(verifyAuthSchema);

export const loginValidate = validationInput(userLoginSchema);