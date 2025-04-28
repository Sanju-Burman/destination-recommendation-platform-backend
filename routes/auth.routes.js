const express = require('express');
const { login, signup, refresh, logout } = require('../controllers/auth.controller');
const { verifyToken } = require('../middlewares/Auth.middleware');
const router = express.Router();

router.get('/', (req, res) => {
    res.status(200).json("Home page running");
});
router.post('/login',login );
router.post('/logout', logout);
router.post('/signup', signup);
router.post('/refresh', refresh);
router.post('/data',verifyToken, (req, res) => {
    res.json("protected page running");
    
});

module.exports = router;