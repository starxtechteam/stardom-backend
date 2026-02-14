import express from "express";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import cors from "cors";
import logger from "./middlewares/logger.ts";
import swaggerUi from "swagger-ui-express";
import { ENV } from "./config/env.ts";
import { swaggerSpec } from "./config/swagger.ts";
import apiRoutes from "./routes/api.routes.ts";
import { errorMiddleware } from "./middlewares/error.middleware.ts";
import "./config/prisma.config.ts";
import "./jobs/email-worker.js";

const app = express();

app.use(helmet());
app.use(logger);
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ENV.ALLOWED_ORIGINS.split(","),
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],  
}));

// Global rate limiting
const globalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// app.set("trust proxy", true);
app.use(globalRateLimit);

app.use(compression());

// Swagger documentation
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const appFilePath = fileURLToPath(import.meta.url);
const appDirPath = path.dirname(appFilePath);
const publicDirCandidates = [
  path.join(process.cwd(), "public"),
  path.join(process.cwd(), "src", "public"),
  path.join(appDirPath, "public"),
];
const publicDirPath = publicDirCandidates.find((dirPath) => fs.existsSync(dirPath));

app.use("/public", express.static(publicDirPath ?? publicDirCandidates[0], {
  dotfiles: "deny",
  etag: true,
  index: false,
  maxAge: "7d",
  immutable: true
}));
app.use("/api/v1", apiRoutes);
app.use(errorMiddleware);

export default app;
