const jwt = require('jsonwebtoken');
const TokenBlacklist = require('../models/tokenBlocking.model');

const verifyToken = async (req, res, next) => {
    const token = req.headers["authorization"];
    // console.log(token);
    if (!token) return res.status(401).json({ error: "Access denied, token require" });
    try {
        const blacklisted = await TokenBlacklist.findOne({ token });
        if (blacklisted) return res.status(401).json({ message: 'blacklisted token' });
        // console.log(blacklisted);

        jwt.verify(token, process.env.JWT_ACCESS_KEY, (err, decoded) => {
            if (err) {
                if (err.name === 'TokenExpiredError') {
                    return res.status(401).json({ message: 'Token expired' });
                }
                return res.status(401).json({ message: 'Invalid token in verifying' });
            }
            req.user = decoded;
            next();
        });
    } catch (error) {
        res.status(401).json({ error: "Invalid token" });
    }
}
const adminChecks =(req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ message: 'Admin access required' });
    }
};
module.exports = { verifyToken,adminChecks };