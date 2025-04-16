const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { MAX_LOGIN_ATTEMPTS, LOCKOUT_DURATION_HOURS } = require('../config/constants');

const AdminSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  otp: {
    code: {
      type: String,
      match: [/^\d{6}$/, 'OTP must be a 6-digit number']
    },
    expiresAt: Date
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date
  },
  isVerified: {
    type: Boolean,
    default: false
  }
}, { timestamps: true }); 

// Compare entered password with hashed password
AdminSchema.methods.comparePassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Hash password before saving
AdminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Check if account is currently locked
AdminSchema.methods.isLocked = function() {
  return this.lockUntil && this.lockUntil > Date.now();
};

// Increment login attempts
AdminSchema.methods.incrementLoginAttempts = async function() {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    this.loginAttempts = 1;
    this.lockUntil = undefined;
  } else {
    this.loginAttempts += 1;
    if (this.loginAttempts >= MAX_LOGIN_ATTEMPTS && !this.isLocked()) {
      this.lockUntil = new Date(Date.now() + LOCKOUT_DURATION_HOURS * 60 * 60 * 1000);
    }
  }
  await this.save();
};

// Reset login attempts on successful login
AdminSchema.methods.resetLoginAttempts = async function() {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  await this.save();
};

module.exports = mongoose.model('Admin', AdminSchema);
