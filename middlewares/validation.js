const { body, validationResult } = require('express-validator');
const ApiError = require('../utils/errorHandler');

const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));
    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    const errorMessages = errors.array().map(err => err.msg);
    next(new ApiError(400, errorMessages[0]));
  };
};

// Admin login validation
const validateAdminLogin = validate([
  body('email').isEmail().normalizeEmail().withMessage('Invalid email format'),
  body('password').notEmpty().withMessage('Password is required')
]);

// OTP validation
const validateOTP = validate([
  body('email').isEmail().normalizeEmail().withMessage('Invalid email format'),
  body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
]);

// Location validation
const validateLocation = validate([
  body('name').trim().notEmpty().withMessage('Location name is required'),
  body('type').isIn(['country', 'state', 'city']).withMessage('Invalid location type'),
  body('parentId').optional().isMongoId().withMessage('Invalid parent ID')
]);

module.exports = {
  validateAdminLogin,
  validateOTP,
  validateLocation,
};
