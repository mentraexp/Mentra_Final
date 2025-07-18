const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const User = require('../models/User');
const Parent = require('../models/Parent');
const Tutor = require('../models/Tutor');
const VerificationToken = require('../models/VerificationToken');
const OtpToken = require('../models/OtpToken');
const { sendMail, sendOtpMail } = require('../utils/mailer');


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

router.post('/forgot-password/send-otp', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const otp = crypto.randomInt(100000, 999999).toString();
    const expiresAt = new Date(Date.now() + 3 * 60 * 60 * 1000); // 3 hours

    await OtpToken.deleteMany({ email }); // Clear previous OTPs
    await OtpToken.create({ email, otp, expiresAt });

    await sendOtpMail(email, otp);

    res.json({ success: true, message: 'OTP sent to your email.' });
  } catch (e) {
    console.error('Error sending OTP:', e);
    res.status(500).json({ success: false, message: 'Failed to send OTP', error: e.message });
  }
});

// 2️⃣ Reset Password
router.post('/forgot-password/reset', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const record = await OtpToken.findOne({ email, otp });
    if (!record || Date.now() > new Date(record.expiresAt).getTime()) {
      return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
    }

    if (!/^.{8,}$/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/\d/.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters, include an uppercase letter and a number.'
      });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await User.findOneAndUpdate({ email }, { password: hashed });

    await OtpToken.deleteMany({ email });

    res.json({ success: true, message: 'Password reset successful. You can now login.' });
  } catch (e) {
    console.error('Password reset error:', e);
    res.status(500).json({ success: false, message: 'Password reset failed', error: e.message });
  }
});

module.exports = router;
