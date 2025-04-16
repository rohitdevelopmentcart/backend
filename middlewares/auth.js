const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../config/constants');
const ApiError = require('../utils/errorHandler');

const auth = (roles = []) => {
  return async (req, res, next) => {
    try {
      // Get token from header
      const token = req.header('Authorization')?.replace('Bearer ', '');
      if (!token) {
        throw new ApiError(401, 'Authentication required');
      }

      // Verify token
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;

      // Check role if specified
      if (roles.length && !roles.includes(decoded.role)) {
        throw new ApiError(403, 'Forbidden - Insufficient permissions');
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

module.exports = auth;