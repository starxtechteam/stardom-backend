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
  requestedAt: string;
  device: string;
}

export async function resetPasswordOtp({ email, otp, requestedAt, device }: SendOtpEmailProps): Promise<boolean> {
  const templatePath = path.join(__dirname, "../templates/reset-password-otp.ejs");

  // Render EJS template
  const html: string = await ejs.renderFile(templatePath, {
    appName: ENV.APP_NAME,
    otp,
    expiresIn: AUTH_OTP.EXPIRES_IN / 60,
    requestedAt: requestedAt,
    device: device,
    year: new Date().getFullYear(),
  });

  // Send email
  const result = await sendEmail(
    email,
    "Reset Password OTP",
    html
  );

  if (!result.success) {
    console.error("Failed to send OTP email:", result.error);
    return false;
  }

  return true;
}
