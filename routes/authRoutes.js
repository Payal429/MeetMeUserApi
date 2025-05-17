const express = require('express');
const router = express.Router();

// Import the updated user controller functions
const {
    onboardUser,
    verifyOtp,
    setPassword,
    login, 
    getUserTypeById,
    resendOtp,
    getUserById
} = require('../controllers/authController.js');

// Route to onboard a user and send OTP
router.post('/onboard', onboardUser);

// Route to verify OTP and set password
router.post('/verify-otp', verifyOtp);

// Route to verify OTP and set password
router.post('/set-password', setPassword);

// Route for user login after setting password
router.post('/login', login);

// Route for getting the user type
router.post('/get-usertype', getUserTypeById);

// Route to resend the otp
router.post('/resend-otp', resendOtp);

// Route to get the user by idnum
router.get('/user/:idNum', getUserById);


module.exports = router;
