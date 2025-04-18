const mongoose = require('mongoose');

const StudentTypeSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: ['school', 'college', 'institute']
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  price: {
    type: Number,
    required: true,
    min: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index to prevent duplicates
StudentTypeSchema.index({ type: 1, name: 1 }, { unique: true });

module.exports = mongoose.model('StudentType', StudentTypeSchema);