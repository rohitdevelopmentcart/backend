const nodemailer = require('nodemailer');
require('dotenv').config();

// Create SMTP transporter using MailerSend SMTP credentials
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  },
  tls: {
    // Do not fail on invalid certs
    rejectUnauthorized: false
  }
});

// Verify connection configuration
transporter.verify((error) => {
  if (error) {
    console.error('SMTP connection error:', error);
  } else {
    console.log('MailerSend SMTP server is ready to take our messages');
  }
});

const sendEmail = async (to, subject, text, html) => {
  try {
    await transporter.sendMail({
      from: `"${process.env.MAILERSEND_SENDER_NAME || 'Admin Panel'}" <${process.env.SMTP_USER}>`,
      to,
      subject,
      text,
      html
    });
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
};

module.exports = sendEmail;