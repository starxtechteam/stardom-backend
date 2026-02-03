import ejs from "ejs";
import path from "path";
import { fileURLToPath } from "url";
import sendEmail from "../../utils/mailSender.js"; 
import { ENV } from "../../config/env.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface SendOtpEmailProps {
  email: string;
  otp: string;
  expiresIn: number
}

export async function sendAdminLoginOtp({ email, otp, expiresIn }: SendOtpEmailProps): Promise<boolean> {
  const templatePath = path.join(__dirname, "../templates/admin-login.ejs");

  // Render EJS template
  const html: string = await ejs.renderFile(templatePath, {
    appName: ENV.APP_NAME,
    otp,
    expiresIn,
    year: new Date().getFullYear(),
  });

  // Send email
  const result = await sendEmail(
    email,
    "Admin Login OTP",
    html
  );

  if (!result.success) {
    console.error("Failed to send Admin Login OTP email:", result.error);
    return false;
  }

  return true;
}
