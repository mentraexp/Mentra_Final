const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const User = require('../models/User');
const Parent = require('../models/Parent');
const Tutor = require('../models/Tutor');
const VerificationToken = require('../models/VerificationToken');
const sendMail = require('../utils/mailer');

router.post('/register', async (req, res) => {
  const { name, email, phone, password, role } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ name, email, phone, password: hashedPassword, role });

    // Create role-specific profile
    if (role === 'parent') {
      await Parent.create({ userId: newUser._id });
    } else if (role === 'tutor') {
      await Tutor.create({ userId: newUser._id });
    }

    const token = crypto.randomBytes(32).toString('hex');
    await VerificationToken.create({ userId: newUser._id, token });

    await sendMail(email, 'Verify Your Email', 'verifyEmail', {
      link: `https://mentra.app/verify-email/${newUser._id}/${token}`
    });

    res.json({ message: 'Registration successful, check your email to verify.' });
  } catch (e) {
    res.status(500).json({ message: 'Error registering user', error: e.message });
  }
});

router.get('/verify-email/:userId/:token', async (req, res) => {
  const { userId, token } = req.params;
  try {
    const record = await VerificationToken.findOne({ userId, token });
    if (!record) return res.status(400).json({ message: 'Invalid or expired link' });

    await User.findByIdAndUpdate(userId, { isVerified: true });
    await VerificationToken.findByIdAndDelete(record._id);

    res.json({ message: 'Email verified successfully. You can now log in.' });
  } catch (e) {
    res.status(500).json({ message: 'Verification failed', error: e.message });
  }
});

module.exports = router;
