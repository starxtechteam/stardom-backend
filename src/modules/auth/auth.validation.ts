import { z } from 'zod';
import { validationInput } from  "../../utils/validation.ts";

const usernameSchema = z.object({
  username: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^[a-z][a-z0-9._]{2,29}$/),
});

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

const verifyRegistrationSchema = z.object({
  token: z.string('Token is required'),
  otp: z.string('OTP is required').min(6, 'OTP must be 6 digit').max(6, 'OTP must be 6 digit')
})

export const registerValidation = validationInput(registerSchema);
export const registerValidation2 = validationInput(verifyRegistrationSchema);