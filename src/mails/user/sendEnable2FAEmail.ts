import ejs from "ejs";
import path from "path";
import { fileURLToPath } from "url";
import sendEmail from "../../utils/mailSender.js";
import { ENV } from "../../config/env.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface SendOtpEmailProps {
  email: string;
  device: string;
}

export async function sendEnable2FAEmail({
  email,
  device,
}: SendOtpEmailProps): Promise<boolean> {
  const templatePath = path.join(__dirname, "../templates/enable-2fa-mail.ejs");

  const enabledAt = new Intl.DateTimeFormat("en-IN", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Asia/Kolkata",
  }).format(new Date());

  // Render EJS template
  const html: string = await ejs.renderFile(templatePath, {
    appName: ENV.APP_NAME,
    year: new Date().getFullYear(),
    enabledAt,
    device,
  });

  // Send email
  const result = await sendEmail(email, "Enable Two-Factor Authentication", html);

  if (!result.success) {
    console.error("Failed to send Welcome email:", result.error);
    return false;
  }

  return true;
}
