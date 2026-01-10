import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT),
  secure: process.env.EMAIL_SECURE === "true", // true for 465
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/**
 * Send email with status
 */
export default async function sendEmail(email, subject, html) {
  try {
    // 1️⃣ Verify SMTP first
    await transporter.verify();

    // 2️⃣ Send email
    const info = await transporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject,
      html,
    });

    return {
      success: true,
      message: "Email sent successfully",
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected,
    };

  } catch (error) {
    return {
      success: false,
      message: "Email sending failed",
      error: error.message,
      code: error.code,
      response: error.response,
    };
  }
}
