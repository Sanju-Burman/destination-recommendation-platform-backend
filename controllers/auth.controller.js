const User = require('../models/user.model');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const TokenBlacklist=require('../models/tokenBlocking.model')

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    // console.log(email,password);
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid password" });

    }
    const payload = { userId: user._id, name:user.username, email: user.email };
    const accessToken = jwt.sign(
      payload,
      process.env.JWT_ACCESS_KEY,
      { expiresIn: '1d' }
    );
    const refreshToken = jwt.sign(
      payload,
      process.env.JWT_REFRESH_KEY,
      { expiresIn: '7d' }
    );
    res.status(200).json({ payload,accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({
      message: "Login failed",
      error: error.message
    });
  }
};

const signup = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }
    const solt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, solt);
    const newUser = new User({ username, email, password:hashPassword });
    await newUser.save();
    res.status(201).json({
      message: "User registered successfully",
      user: { username, email }
    });
  } catch (error) {
    res.status(500).json({ message: "Registration failed", error: error.message });
  }
};

const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401)
        .json({
            message: 'Refresh Token required'
          });
    }
    const blacklisted = await TokenBlacklist.findOne({ token: refreshToken });
    if (blacklisted) {
      return res.status(401).json({ message: 'Invalid token' });
    }

    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, decoded) => {
      if (err) return res.status(401).json({ message: 'Invalid refresh token' });

      const accessToken = jwt.sign(
        { userId: decoded.userId, role: decoded.role },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: '1d' }
      );

      res.json({ accessToken });
    });
  } catch (error) {
    res.status(500).json({ message: 'Refresh failed', error });
  }
}

const logout = async (req, res) => {
  try {
    const { accessToken, refreshToken } = req.body;

    const accessTokenExp = jwt.decode(accessToken).exp;
    const refreshTokenExp = jwt.decode(refreshToken).exp;

    await TokenBlacklist.create([
      {
        token: accessToken,
        type: 'access',
        expiresAt: new Date(accessTokenExp * 1000)
      },
      {
        token: refreshToken,
        type: 'refresh',
        expiresAt: new Date(refreshTokenExp * 1000)
      }
    ]);

    res.json({ message: 'Logout successful' });
  } catch (error) {
    res.status(500).json({ message: 'Logout failed', error });
  }
}
module.exports = { login, signup, refresh,logout };