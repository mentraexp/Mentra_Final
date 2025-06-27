const nodemailer = require('nodemailer');
const path = require('path');
const ejs = require('ejs');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MENTRA_EMAIL,
    pass: process.env.MENTRA_EMAIL_PASS
  }
});

const sendMail = async (to, subject, templateName, data = {}) => {
  const templatePath = path.join(__dirname, 'templates', `${templateName}.ejs`);
  const html = await ejs.renderFile(templatePath, data);
  await transporter.sendMail({ from: 'Mentra <mentraedu@gmail.com>', to, subject, html });
};

module.exports = sendMail;