const express = require('express');
const router = express.Router();
const User = require('../models/User.js');
const jwt = require('jsonwebtoken');

// Generate an access token (short-lived)
// Generate an access token (short-lived)
const generateAccessToken = (user) => {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: '15m', // e.g., 15 minutes
  });
};

// Generate a refresh token (long-lived)
const generateRefreshToken = (user) => {
    return jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, {
      expiresIn: '7d', // e.g., 7 days
    });
};

// @desc    Register a new user
// @route   POST /api/auth/register
router.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const userExists = await User.findOne({ username });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const user = await User.create({ username, password });

    if (user) {
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);

      user.refreshTokens.push(refreshToken);
      await user.save();

      res.status(201).json({
        _id: user._id,
        username: user.username,
        accessToken,
        refreshToken,
      });
    } else {
      res.status(400).json({ message: 'Invalid user data' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// @desc    Auth user & get tokens
// @route   POST /api/auth/login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (user && (await user.matchPassword(password))) {
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);

      user.refreshTokens.push(refreshToken);
      await user.save();

      res.json({
        _id: user._id,
        username: user.username,
        accessToken,
        refreshToken,
      });
    } else {
      res.status(401).json({ message: 'Invalid username or password' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// @desc    Refresh access token
// @route   POST /api/auth/refresh
router.post('/refresh', async (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(401).json({ message: 'No refresh token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);

        if (!user || !user.refreshTokens.includes(token)) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        const accessToken = generateAccessToken(user._id);
        res.json({ accessToken });

    } catch (error) {
        return res.status(403).json({ message: 'Invalid refresh token' });
    }
});

// @desc    Logout user
// @route   POST /api/auth/logout
router.post('/logout', async (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ message: 'No refresh token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);

        if (user) {
            user.refreshTokens = user.refreshTokens.filter(rt => rt !== token);
            await user.save();
        }

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        // Even if token is invalid, we can just say it's successful
        res.json({ message: 'Logged out successfully' });
    }
});


module.exports = router;
