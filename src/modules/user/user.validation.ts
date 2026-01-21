import { z } from "zod";
import { validationInput } from "../../utils/validation.ts";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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

export const tokenSchema = z.object({
  token: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9\-_]+$/, "Invalid token format")
    .min(32, "Token is too short")
    .max(128, "Token is too long"),
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

const updateEmail = z.object({
  email: z.email("Email is required").regex(emailRegex, {message:"Invaild email"})
})

const updateEmailStep2 = tokenSchema.extend({
  otp: z.string({ message: 'OTP is required' }).length(6, 'Invalid OTP'),
})

const urlWithDomain = (domains: string[], message: string) =>
  z
    .url({ message })
    .refine((url) => {
      try {
        const hostname = new URL(url).hostname.replace(/^www\./, "");
        return domains.includes(hostname);
      } catch {
        return false;
      }
    }, { message });

export const updateSocialSchema = z.object({
  websiteUrl: z
    .url({ message: "Website URL must be a valid URL." })
    .optional(),

  socialTwitter: urlWithDomain(
    ["twitter.com", "x.com"],
    "Twitter URL must be from twitter.com or x.com"
  ).optional(),

  socialFacebook: urlWithDomain(
    ["facebook.com", "www.facebook.com"],
    "Facebook URL must be from facebook.com"
  ).optional(),

  socialLinkedin: urlWithDomain(
    ["linkedin.com", "www.linkedin.com"],
    "LinkedIn URL must be from linkedin.com"
  ).optional(),

  socialInstagram: urlWithDomain(
    ["instagram.com", "www.instagram.com"],
    "Instagram URL must be from instagram.com"
  ).optional(),
});
export const updateProfileValidation = validationInput(updateProfileSchema);
export const updateSocialValidation = validationInput(updateSocialSchema);
export const changeEmailValidation = validationInput(updateEmail);
export const changeEmailValidation2 = validationInput(updateEmailStep2);
