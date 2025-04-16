const jwt = require('jsonwebtoken');
const Admin = require('../../models/Admin');
const bcrypt = require('bcryptjs');
// const FailedLogin = require('../../models/FailedLogin');
const {
  generateOTP,
  getOTPExpiry,
} = require('../../services/otpService');
const {
  sendOTPEmail,
  sendLockoutEmail,
  sendUnauthorizedAccessEmail,
} = require('../../services/emailService');
const { JWT_SECRET } = require('../../config/constants');
const { ApiError }= require('../../utils/errorHandler');
const { logger, logFailedAttempt } = require('../../utils/logger');
const apiResponse = require('../../utils/apiResponse');

const createAdmin = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    // Check if admin already exists
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(409).json({ success: false, message: 'Admin already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create admin
    const newAdmin = await Admin.create({
      email,
      password: hashedPassword,
    });

    // Respond
    return res.status(201).json({
      success: true,
      message: 'Admin created successfully',
      data: {
        id: newAdmin._id,
        email: newAdmin.email,
      },
    });

  } catch (error) {
    next(error); // Pass error to the error handler middleware
  }
};

/**
 * Admin Login Handler
 * Validates credentials, sends OTP, handles login attempts and lockouts
 */
const adminLogin = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      throw new ApiError(400, 'Please enter required fields');
    }
    
    // Check if admin exists
    let admin = await Admin.findOne({ email });
    if (!admin) {
      await sendUnauthorizedAccessEmail(email);
      await logFailedAttempt(email, req.ip);
      throw new ApiError(401, 'Invalid email or password');
    }

    // Check if account is locked
    if (admin.isLocked && admin.isLocked()) {
      throw new ApiError(
        403,
        'Account is temporarily locked. Please try again later.'
      );
    }

    // Validate password
    // const isMatch = await admin.comparePassword(password);
const isMatch= true;
    if (!isMatch) {
      await admin.incrementLoginAttempts();
      await logFailedAttempt(email, req.ip);

      // Re-fetch updated admin state
      const updatedAdmin = await Admin.findOne({ email });
      if (updatedAdmin.isLocked && updatedAdmin.isLocked()) {
        await sendLockoutEmail(email);
      }
      throw new ApiError(401, 'Invalid email or password');
    }
    // Reset login attempts
    await admin.resetLoginAttempts();

    // Generate and save OTP
    const otp = generateOTP();
    console.log(otp,"OTP");
    const otpExpiry = getOTPExpiry();
    admin.otp = { code: otp, expiresAt: otpExpiry };
    await admin.save();

    // Send OTP
    await sendOTPEmail(email, otp);

    return apiResponse(res, 200, true, 'OTP sent to your email');
  } catch (error) {
    next(error);
  }
};
/**
 * OTP Verification Handler
 * Verifies OTP, returns JWT if successful
 */
const verifyOTP = async (req, res, next) => {
  try {
    const { email, otp } = req.body;
    console.log('OTP from body:', otp);    if (!email || !otp) {
      throw new ApiError(400, 'Please enter required fields');
    }
    
    const admin = await Admin.findOne({ email });
    if (!admin) {
      throw new ApiError(404, 'Admin not found');
    }
    // Check if OTP matches and is not expire  
    if (
      !admin.otp ||
      String(admin.otp.code) !== String(otp) ||
      new Date() > new Date(admin.otp.expiresAt)
    ) {
      throw new ApiError(400, 'Invalid or expired OTP');
    }

    // Clear OTP & mark verified
    admin.otp = undefined;
    admin.isVerified = true;
    await admin.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: admin._id, email: admin.email, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return apiResponse(res, 200, true, 'Login successful', { token });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createAdmin,
  adminLogin,
  verifyOTP,
};
