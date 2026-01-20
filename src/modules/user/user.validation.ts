import { z } from "zod";
import { validationInput } from "../../utils/validation.ts";

const usernameSchema = z.object({
  username: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^[a-z][a-z0-9._]{2,29}$/, {
      message:
        "Username must start with a letter and contain only lowercase letters, numbers, dots, or underscores (3–30 chars).",
    }),
});

const updateProfileSchema = usernameSchema.extend({
  first_name: z
    .string()
    .min(2, { message: "First name must be at least 2 characters long." })
    .max(50, { message: "First name must be at most 50 characters long." })
    .optional(),

  last_name: z
    .string()
    .min(2, { message: "Last name must be at least 2 characters long." })
    .max(50, { message: "Last name must be at most 50 characters long." })
    .optional(),

  bio: z
    .string()
    .max(160, { message: "Bio must be at most 160 characters long." })
    .optional(),

  avatarUrl: z
    .url({ message: "Avatar URL must be a valid URL." })
    .optional(),

  bannerUrl: z
    .url({ message: "Banner URL must be a valid URL." })
    .optional(),

  gender: z
    .enum(["male", "female", "other"], {
      message: "Gender must be one of: male, female, or other.",
    })
    .optional(),

  birthdate: z
    .string()
    .refine((val) => !isNaN(Date.parse(val)), {
      message: "Birthdate must be a valid ISO date string.",
    })
    .optional(),

  location: z
    .string()
    .max(100, { message: "Location must be at most 100 characters long." })
    .optional(),
});

export const updateProfileValidation = validationInput(updateProfileSchema);
