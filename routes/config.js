// routes/config.js
const router = require('express').Router();

router.get('/', (req, res) => {
  res.json({
    googleClientId: process.env.GOOGLE_CLIENT_ID
  });
});

module.exports = router;
