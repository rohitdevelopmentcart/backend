class ApiError extends Error {
    constructor(statusCode, message, isOperational = true, stack = '') {
      super(message);
      this.statusCode = statusCode;
      this.isOperational = isOperational;
      if (stack) {
        this.stack = stack;
      } else {
        Error.captureStackTrace(this, this.constructor);
      }
    }
  }
  
  const errorHandler = (err, req, res, next) => {
    const statusCode = err.statusCode || 500;
    const message = err.message || 'Internal Server Error';
    
    // Log the error for debugging
    console.error(`[${req.method}] ${req.path} >> StatusCode:: ${statusCode}, Message:: ${message}`);
    
    res.status(statusCode).json({
      success: false,
      message,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
  };
  
  module.exports = {
    ApiError,
    errorHandler
  };