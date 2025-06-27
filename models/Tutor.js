const mongoose = require('mongoose');
const tutorSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    pincode: String,
    subjects: [String],
    experience: String,
    rate: Number,
    qualifications: [{
      degree: String,
      specialization: String,
      proof: {
        data: Buffer,
        contentType: String
      },
      status: {
        type: String,
        enum: ['pending', 'verified', 'rejected'],
        default: 'pending'
      }
    }],
    kycStatus: {
      type: String,
      enum: ['not_verified', 'pending', 'verified', 'rejected'],
      default: 'not_verified'
    },
    aadhaarNumber: String,
    availability: [{
      date: String,
      slots: [{
        time: String,
        isBooked: { type: Boolean, default: false }
      }]
    }]
  });
  
  module.exports = mongoose.model('Tutor', tutorSchema);
  