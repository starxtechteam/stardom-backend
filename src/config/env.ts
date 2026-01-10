import { config } from "dotenv";
import { z } from "zod";

config();

const envSchema = z.object({
  PORT: z.coerce.number().default(3000),
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),

  DATABASE_URL: z.string(),

  REDIS_HOST: z.string(),
  REDIS_PORT: z.coerce.number().default(6379),

  JWT_ACCESS_SECRET: z.string(),
  JWT_ACCESS_EXPIRES_IN: z.string().default("15m"),
  JWT_REFRESH_SECRET: z.string(),
  JWT_REFRESH_EXPIRES_IN: z.string().default("7d"),

  ALLOWED_ORIGINS: z.string().default("*"),
});

export const ENV = envSchema.parse(process.env);
