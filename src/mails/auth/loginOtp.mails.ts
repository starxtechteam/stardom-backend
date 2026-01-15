import ejs from "ejs";
import path from "path";
import { fileURLToPath } from "url";
import sendEmail from "../../utils/mailSender.js"; 
import { ENV } from "../../config/env.ts";
import { AUTH_OTP } from "../../constants/auth.constants.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface SendOtpEmailProps {
  email: string;
  otp: string;
}

export async function sendLoginOtp({ email, otp }: SendOtpEmailProps): Promise<boolean> {
  const templatePath = path.join(__dirname, "../templates/loginotp.ejs");

  // Render EJS template
  const html: string = await ejs.renderFile(templatePath, {
    appName: ENV.APP_NAME,
    otp,
    expiresIn: AUTH_OTP.EXPIRES_IN / 60,
    year: new Date().getFullYear(),
  });

  // Send email
  const result = await sendEmail(
    email,
    "Your OTP Code",
    html
  );

  if (!result.success) {
    console.error("Failed to send OTP email:", result.error);
    return false;
  }

  return true;
}
