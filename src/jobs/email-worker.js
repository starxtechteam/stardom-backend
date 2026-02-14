import { Worker } from "bullmq";
import IORedis from "ioredis";
import sendEmail from "../utils/mailSender";
import { ENV } from "../config/env";

// Create Redis connection
const connection = new IORedis({
  host: "127.0.0.1",
  port: 6379,
  maxRetriesPerRequest: null,
});

async function emailWorker(jobs) {
  // console.log("Data: ", jobs);

  await sendEmail(
    jobs.data.email,
    jobs.data.subject,
    jobs.data.html
  );

  if(ENV.NODE_ENV === "development"){
    console.log(`Mail Sent to ${jobs.data.email}`)
  }
}

new Worker("email-worker", emailWorker, {connection});