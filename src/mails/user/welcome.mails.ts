import ejs from "ejs";
import path from "path";
import { fileURLToPath } from "url";
import sendEmail from "../../utils/mailSender.js"; 
import { ENV } from "../../config/env.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface SendOtpEmailProps {
  email: string;
  name: string;
}

export async function sendWelcomeEmail({ email, name }: SendOtpEmailProps): Promise<void> {
  const templatePath = path.join(__dirname, "../templates/welcome.ejs");

  // Render EJS template
  const html: string = await ejs.renderFile(templatePath, {
    appName: ENV.APP_NAME,
    name: name,
    year: new Date().getFullYear(),
  });

  // Send email
  const result = await sendEmail(
    email,
    "Welcome",
    html
  );

  if (!result.success) {
    console.error("Failed to send Welcome email:", result.error);
    throw new Error(result.error);
  }
}
