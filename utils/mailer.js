const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MENTRA_EMAIL,
    pass: process.env.MENTRA_EMAIL_PASS
  }
});

// Verify mailer config on startup
transporter.verify(function (error, success) {
  if (error) {
    console.log('❌ Mailer config error:', error);
  } else {
    console.log('✅ Mailer ready');
  }
});

// General sendMail (if you need it)
const sendMail = async (to, subject, html) => {
  await transporter.sendMail({
    from: 'Mentra <mentraedu@gmail.com>',
    to,
    subject,
    html
  });
};

// Hardcoded HTML OTP mail
async function sendOtpMail(email, otp) {
  const html = `
    <h2>Mentra Password Reset</h2>
    <p>Hello,</p>
    <p>Your OTP to reset your Mentra password is:</p>
    <h3>${otp}</h3>
    <p>This OTP is valid for <strong>3 hours</strong>.</p>
    <p>If you didn’t request this, please ignore this email.</p>
    <br>
    <p>— Mentra Team</p>
  `;
  await sendMail(email, 'Reset your Mentra Password', html);
}

module.exports = { sendMail, sendOtpMail };
