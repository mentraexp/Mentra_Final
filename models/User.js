const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  phone: { type: String, unique: true, required: true },
  password: String,
  isVerified: { type: Boolean, default: false },
  isGuest: { type: Boolean, default: false },
  role: { type: String, enum: ['parent', 'tutor', 'admin'], required: true },
  googleId: String,
  lastLogin: Date,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);