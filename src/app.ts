import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import cors from "cors";
import { ENV } from "./config/env.ts";
import apiRoutes from "./routes/api.routes.ts";
import { errorMiddleware } from "./middlewares/error.middleware.ts";
import "./config/prisma.config.ts";

const app = express();

app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());
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

app.use("/api/v1", apiRoutes);
app.use(errorMiddleware);

export default app;
