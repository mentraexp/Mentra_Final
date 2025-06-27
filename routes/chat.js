const mongoose = require('mongoose');

const express = require('express');
const router = express.Router();
const Conversation = require('../models/Conversation');
const Message = require('../models/Message');
const sendMail = require('../utils/mailer');

// Create or retrieve conversation
router.post('/conversation', async (req, res) => {
  const { user1, user2 } = req.body;
  let convo = await Conversation.findOne({ participants: { $all: [user1, user2] } });
  if (!convo) {
    convo = new Conversation({ participants: [user1, user2], lastUpdated: new Date() });
    await convo.save();
  }
  res.json(convo);
});

// Send message
router.post('/message', async (req, res) => {
  const { conversationId, senderId, text } = req.body;
  const message = new Message({ conversationId, senderId, text });
  await message.save();

  const convo = await Conversation.findById(conversationId);
  convo.lastMessage = text;
  convo.lastUpdated = new Date();
  await convo.save();

  // Email notification logic can go here
  // sendMail(toUserEmail, 'New Message', 'chatNotification', { text })

  res.json(message);
});

module.exports = router;