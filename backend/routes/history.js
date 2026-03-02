const express = require('express');
const router = express.Router();
const { getAllScans } = require('../db/database');

router.get('/history', (req, res) => {
  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));

  try {
    const data = getAllScans({ page, limit });
    res.json(data);
  } catch (err) {
    console.error('History error:', err.message);
    res.status(500).json({ error: 'Failed to fetch history.' });
  }
});

module.exports = router;
