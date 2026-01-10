import { z } from 'zod';
import { validationInput } from  "../../utils/core.ts";

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

export const registerValidation = validationInput(registerSchema);