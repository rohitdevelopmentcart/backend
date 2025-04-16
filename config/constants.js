module.exports = {
    OTP_LENGTH: 6,
    OTP_EXPIRY_MINUTES: 5,
    MAX_LOGIN_ATTEMPTS: 3,
    LOCKOUT_DURATION_HOURS: 24,
    PASSWORD_RESET_EXPIRY_MINUTES: 15,
    JWT_SECRET: process.env.JWT_SECRET || 'your-secret-key',
    JWT_EXPIRY: '24h',
  };
