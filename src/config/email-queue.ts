import { Queue } from "bullmq";
import { ENV } from "./env.ts";

export const emailQueue = new Queue("email-worker", {
    connection: {
        host: ENV.REDIS_HOST,
        port: ENV.REDIS_PORT
    }
});
