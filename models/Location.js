const mongoose = require('mongoose');

const LocationSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    required: true,
    enum: ['country', 'state', 'city']
  },
  parent: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Location',
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Index to prevent duplicates
LocationSchema.index({ name: 1, type: 1, parent: 1 }, { unique: true });

module.exports = mongoose.model('Location', LocationSchema);