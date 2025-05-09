const express = require('express');
const router = express.Router();

// Import the updated user controller functions
const {
    onboardUser,
    verifyOtp,
    setPassword,
    login
} = require('../controllers/authController.js');

// Route to onboard a user and send OTP
router.post('/onboard', onboardUser);

// Route to verify OTP and set password
router.post('/verify-otp', verifyOtp);

// Route to verify OTP and set password
router.post('/set-password', setPassword);

// Route for user login after setting password
router.post('/login', login);

module.exports = router;
