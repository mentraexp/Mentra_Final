const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
// const crypto = require('crypto');
const { sendMail, sendOtpMail } = require('../utils/mailer');

const User = require('../models/User');
const Parent = require('../models/Parent');
const Tutor = require('../models/Tutor');
const VerificationToken = require('../models/VerificationToken');


const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
};


router.post('/register', async (req, res) => {
  const MAX_RETRIES = 3;
  let attempt = 0;

  while (attempt < MAX_RETRIES) {
    const session = await User.startSession();
    session.startTransaction();

    try {
      const { name, email, phone, password, role, pincode } = req.body;

      // ✅ Validate phone number
      if (!/^[0-9]{10}$/.test(phone)) {
        await session.endSession();
        return res.status(400).json({
          success: false,
          message: 'Phone number must be exactly 10 digits.',
          code: 'INVALID_PHONE'
        });
      }

      // ✅ Validate password strength
      if (!/^.{8,}$/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password)) {
        await session.endSession();
        return res.status(400).json({
          success: false,
          message: 'Password must be at least 8 characters long, include one uppercase letter and one number.',
          code: 'WEAK_PASSWORD'
        });
      }

      // ✅ Check for duplicates
      const existingEmail = await User.findOne({ email });
      if (existingEmail) {
        await session.endSession();
        return res.status(400).json({
          success: false,
          message: 'Email already registered.',
          code: 'EMAIL_EXISTS'
        });
      }

      const existingPhone = await User.findOne({ phone });
      if (existingPhone) {
        await session.endSession();
        return res.status(400).json({
          success: false,
          message: 'Phone number already registered.',
          code: 'PHONE_EXISTS'
        });
      }

      // ✅ Create user + profile in transaction
      const hashedPassword = await bcrypt.hash(password, 10);
      const [newUser] = await User.create([{ name, email, phone, password: hashedPassword, role }], { session });

      if (role === 'parent') {
        await Parent.create([{ userId: newUser._id }], { session });
      } else if (role === 'tutor') {
        if (!pincode || typeof pincode !== 'string' || pincode.length < 4) {
          await session.abortTransaction();
          await session.endSession();
          return res.status(400).json({
            success: false,
            message: 'Area Pincode is required for tutor registration.',
            code: 'PINCODE_REQUIRED'
          });
        }
        await Tutor.create([{ userId: newUser._id, pincode }], { session });
      }

      // ✅ Send notification email
      await sendMail(
        email,
        'Mentra Registration Notification',
        'verifyEmail',
        {}
      );

      await session.commitTransaction();
      session.endSession();

      return res.status(200).json({
        success: true,
        message: 'Registration successful. Email notification sent.'
      });

    } catch (e) {
      await session.abortTransaction();
      await session.endSession();

      if (e.errorLabels?.includes('TransientTransactionError')) {
        attempt++;
        console.warn(`⚠️ Retry ${attempt} - transient transaction error`);
      } else {
        console.error('Registration error:', e);
        return res.status(500).json({
          success: false,
          message: 'Something went wrong. Please try again later.',
          code: 'SERVER_ERROR'
        });
      }
    }
  }

  return res.status(500).json({
    success: false,
    message: 'Too many retry attempts. Try again later.',
    code: 'RETRY_LIMIT_REACHED'
  });
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



router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, message: 'User not found', code: 'USER_NOT_FOUND' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid password', code: 'INVALID_CREDENTIALS' });

    user.lastLogin = new Date();
    await user.save();

    const token = generateToken(user);
    res.json({ success: true, token, user });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Login error', error: e.message });
  }
});

// Google Login
// router.post('/complete-google-signup', async (req, res) => {
//   const session = await User.startSession();
//   session.startTransaction();

//   try {
//     const { token, role, pincode, phone } = req.body;
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     const { email, name, googleId } = decoded;

//     if (!/^[0-9]{10}$/.test(phone)) {
//       throw new Error('Valid 10-digit phone number is required.');
//     }

//     const user = await User.findOne({ email });
//     if (!user) {
//       const [newUser] = await User.create([{ name, email, phone, password: 'GOOGLE_AUTH', googleId, isVerified: true, role }], { session });

//       if (role === 'parent') {
//         await Parent.create([{ userId: newUser._id }], { session });
//       } else if (role === 'tutor') {
//         if (!pincode) throw new Error('Pincode is required for tutor role');
//         await Tutor.create([{ userId: newUser._id, pincode }], { session });
//       }

//       await session.commitTransaction();
//       session.endSession();

//       const newToken = jwt.sign({ id: newUser._id, email, role }, process.env.JWT_SECRET);
//       return res.json({ success: true, token: newToken, user: newUser });
//     } else {
//       await session.abortTransaction();
//       session.endSession();
//       return res.status(400).json({ success: false, message: 'User already exists.' });
//     }
//   } catch (e) {
//     await session.abortTransaction();
//     session.endSession();
//     return res.status(500).json({ success: false, message: 'Google signup failed.', error: e.message });
//   }
// });

router.post('/google-login', async (req, res) => {
  try {
    const { idToken } = req.body;
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    const ticket = await client.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { email } = payload;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(200).json({ success: false, message: 'User not found' });
    }

    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET);
    res.json({ success: true, token, user });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Google login failed', error: e.message });
  }
});


router.post('/complete-google-signup', async (req, res) => {
  const session = await User.startSession();
  session.startTransaction();

  try {
    const { token, role, pincode, phone } = req.body;
    const { OAuth2Client } = require('google-auth-library');
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name, sub: googleId } = payload;

    if (!/^[0-9]{10}$/.test(phone)) {
      throw new Error('Valid 10-digit phone number is required.');
    }

    let user = await User.findOne({ email });

    if (!user) {
      const [newUser] = await User.create([{ name, email, phone, password: 'GOOGLE_AUTH', googleId, isVerified: true, role }], { session });

      if (role === 'parent') {
        await Parent.create([{ userId: newUser._id }], { session });
      } else if (role === 'tutor') {
        if (!pincode) throw new Error('Pincode is required for tutor role');
        await Tutor.create([{ userId: newUser._id, pincode }], { session });
      }

      await session.commitTransaction();
      session.endSession();

      const newToken = jwt.sign({ id: newUser._id, email, role }, process.env.JWT_SECRET);
      return res.json({ success: true, token: newToken, user: newUser });
    } else {
      // If user exists and already registered via Google, skip asking role
      if (!user.googleId) {
        user.googleId = googleId;
        await user.save();
      }

      await session.abortTransaction();
      session.endSession();

      const newToken = jwt.sign({ id: user._id, email: user.email, role: user.role }, process.env.JWT_SECRET);
      return res.status(200).json({ success: true, message: 'User already exists.', token: newToken, user });
    }
  } catch (e) {
    await session.abortTransaction();
    session.endSession();
    return res.status(500).json({ success: false, message: 'Google signup failed.', error: e.message });
  }
});


const OtpToken = require('../models/OtpToken');
const crypto = require('crypto');

router.post('/forgot-password/send-otp', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const otp = crypto.randomInt(100000, 999999).toString();
    const expiresAt = new Date(Date.now() + 3 * 60 * 60 * 1000); // 3 hours

    await OtpToken.deleteMany({ email }); // Clear old OTPs
    await OtpToken.create({ email, otp, expiresAt });

    await sendOtpMail(email, otp); // ✅ Hardcoded email content

    res.json({ success: true, message: 'OTP sent to your email.' });
  } catch (e) {
    console.error('Error sending OTP:', e);
    res.status(500).json({ success: false, message: 'Error sending OTP', error: e.message });
  }
});


router.post('/forgot-password/reset', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const record = await OtpToken.findOne({ email, otp });
    if (!record || new Date() > record.expiresAt) {
      return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
    }

    if (!/^.{8,}$/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/\d/.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters, contain an uppercase letter and a number.'
      });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    await User.findOneAndUpdate({ email }, { password: hashed });

    await OtpToken.deleteMany({ email }); // cleanup

    res.json({ success: true, message: 'Password reset successful' });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Password reset failed', error: e.message });
  }
});


module.exports = router;