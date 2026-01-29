import ejs from "ejs";
import path from "path";
import { fileURLToPath } from "url";
import sendEmail from "../../utils/mailSender.js";
import { ENV } from "../../config/env.ts";
import { Device } from "../../types/auth.types.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface SendOtpEmailProps {
  email: string;
  device: Device;
  requestedAt: string;
}

export async function sendAccountDeletionScheduledEmail({
  email,
  device,
  requestedAt
}: SendOtpEmailProps): Promise<boolean> {
  const templatePath = path.join(
    __dirname,
    "../templates/account-deletion.ejs",
  );

  // Render EJS template
  const html: string = await ejs.renderFile(templatePath, {
    appName: ENV.APP_NAME,
    requestedAt,
    device: device,
    year: new Date().getFullYear(),
  });

  // Send email
  const result = await sendEmail(email, "Account Deletion Scheduled", html);

  if (!result.success) {
    console.error("Failed to Account Deletion Scheduled: ", result.error);
    return false;
  }

  return true;
}
