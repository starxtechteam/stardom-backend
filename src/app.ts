import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import cors from "cors";
import { ENV } from "./config/env.js";
import apiRoutes from "./routes/api.routes.js";
import { errorMiddleware } from "./middlewares/error.middleware.js";
import "./config/prisma.config.js";

const app = express();

app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());
app.use(cors({
    origin: ENV.ALLOWED_ORIGINS.split(","),
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],  
}));

app.use("/api/v1", apiRoutes);
app.use(errorMiddleware);

export default app;
