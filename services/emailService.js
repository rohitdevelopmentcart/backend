const sendEmail = require('../config/email');
const { OTP_EXPIRY_MINUTES, LOCKOUT_DURATION_HOURS } = require('../config/constants');

const sendOTPEmail = async (email, otp) => {
  const subject = 'Your Admin Login OTP';
  const text = `Your OTP for admin login is ${otp}. It will expire in ${OTP_EXPIRY_MINUTES} minutes.`;
  const html = `
    <div>
      <h3>Your Admin Login OTP</h3>
      <p>Your OTP is: <strong>${otp}</strong></p>
      <p>This OTP will expire in ${OTP_EXPIRY_MINUTES} minutes.</p>
    </div>
  `;
  return await sendEmail(email, subject, text, html);
};

const sendLockoutEmail = async (email) => {
  const subject = 'Admin Account Locked';
  const text = `Your admin account has been locked for ${LOCKOUT_DURATION_HOURS} hours due to multiple failed login attempts.`;
  const html = `
    <div>
      <h3>Admin Account Locked</h3>
      <p>Your admin account has been temporarily locked for ${LOCKOUT_DURATION_HOURS} hours due to multiple failed login attempts.</p>
      <p>If this wasn't you, please contact support immediately.</p>
    </div>
  `;
  return await sendEmail(email, subject, text, html);
};

const sendUnauthorizedAccessEmail = async (email, attemptedEmail) => {
  const subject = 'Unauthorized Access Attempt';
  const text = `Someone attempted to access the admin panel using email: ${attemptedEmail}`;
  const html = `
    <div>
      <h3>Unauthorized Access Attempt</h3>
      <p>Someone attempted to access the admin panel using email: <strong>${attemptedEmail}</strong></p>
    </div>
  `;
  return await sendEmail(email, subject, text, html);
};

const sendPasswordResetEmail = async (email, tempPassword) => {
  const subject = 'Your Temporary Password';
  const text = `Your temporary password is: ${tempPassword}. Please change it immediately after logging in.`;
  const html = `
    <div>
      <h3>Temporary Password</h3>
      <p>Your temporary password is: <strong>${tempPassword}</strong></p>
      <p>Please change it immediately after logging in for security reasons.</p>
    </div>
  `;
  return await sendEmail(email, subject, text, html);
};

module.exports = {
  sendOTPEmail,
  sendLockoutEmail,
  sendUnauthorizedAccessEmail,
  sendPasswordResetEmail
};