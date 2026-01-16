import ejs from "ejs";
import path from "path";
import { fileURLToPath } from "url";
import sendEmail from "../../utils/mailSender.ts";
import { ENV } from "../../config/env.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface Enable2FAOtpEmailPayload {
  email: string;
  otp: string;
}

export async function sendEnable2FAOtpEmail({
  email,
  otp
}: Enable2FAOtpEmailPayload): Promise<boolean> {
  const templatePath = path.join(
    __dirname,
    "../templates/enable-2fa-otp.ejs"
  );

  const html = await ejs.renderFile(templatePath, {
    appName: ENV.APP_NAME,
    otp,
    expiresIn: 5,
    year: new Date().getFullYear(),
  });

  const result = await sendEmail(
    email,
    "Your OTP to Enable Two-Factor Authentication",
    html,
  );

  if (!result.success) {
    console.error("Failed to send OTP email:", result.error);
    return false;
  }

  return true;
}
