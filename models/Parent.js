const mongoose = require('mongoose');
const parentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    childName: String,
    childClass: String,
    subjectsNeeded: [String],
    preferredLocation: String
  });
  
  module.exports = mongoose.model('Parent', parentSchema);