const rateLimit = require('express-rate-limit');
const { MAX_LOGIN_ATTEMPTS } = require('../config/constants');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: MAX_LOGIN_ATTEMPTS, // Limit each IP to 3 login attempts per windowMs
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
  handler: (req, res, next, options) => {
    res.status(options.statusCode).json({
      success: false,
      message: options.message
    });
  },
  skipSuccessfulRequests: true
});

module.exports = loginLimiter;