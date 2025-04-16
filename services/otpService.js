const { OTP_LENGTH, OTP_EXPIRY_MINUTES } = require('../config/constants');

const generateOTP = () => {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < OTP_LENGTH; i++) {
    otp += digits[Math.floor(Math.random() * 10)];
  }
  return otp;
};

const isOTPExpired = (expiryDate) => {
  return new Date() > new Date(expiryDate);
};

const getOTPExpiry = () => {
  const expiry = new Date();
  expiry.setMinutes(expiry.getMinutes() + OTP_EXPIRY_MINUTES);
  return expiry;
};

module.exports = {
  generateOTP,
  isOTPExpired,
  getOTPExpiry
};