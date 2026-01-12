import app from "./app.js";
import chalk from "chalk";
import os from "os";
import { ENV } from "./config/env.js";
import {connectRedis} from "./config/redis.config.ts";

app.get("/", (req, res) => {
  res.send("<h1>Welcome to the Stardom Backend API!</h1>");
});

const port = ENV.PORT;

app.listen(port, () => {
  console.clear();
  console.log(chalk.gray("──────────────────────────────────────"));
  console.log(
    chalk.greenBright.bold("🚀 Server Started Successfully\n")
  );

  console.log(
    `${chalk.cyan("📍 URL:")}      ${chalk.white(`http://localhost:${port}`)}`
  );
  console.log(
    `${chalk.cyan("🌍 ENV:")}      ${chalk.yellow(ENV.NODE_ENV)}`
  );
  console.log(
    `${chalk.cyan("🧠 Node:")}     ${process.version}`
  );
  console.log(
    `${chalk.cyan("💻 Platform:")} ${os.platform()} (${os.arch()})`
  );
  console.log(
    `${chalk.cyan("🕒 Time:")}     ${new Date().toLocaleString()}`
  );

  console.log(chalk.gray("──────────────────────────────────────"));
});  

connectRedis();
