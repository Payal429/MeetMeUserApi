const firebaseAdmin = require('firebase-admin');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const path = require('path');

// Firebase Admin setup
const serviceAccountPath = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
//const serviceAccountPath = require(path.resolve(__dirname, process.env.FIREBASE_SERVICE_ACCOUNT));


firebaseAdmin.initializeApp({
  credential: firebaseAdmin.credential.cert(serviceAccountPath)
});

const db = firebaseAdmin.firestore();

// Helper: Generate OTP
const generateOtp = () => Math.random().toString(36).slice(-6);

// Send OTP Email
const sendOtpEmail = async (email, otp, idNum) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  const mailOptions = {
    from: process.env.SMTP_USER,
    to: email,
    subject: 'MeetMe OTP Verification',
    text: `Hi ${idNum},\n\nYour OTP is: ${otp}\n\nUse this to verify your account.`
  };

  await transporter.sendMail(mailOptions);
};

exports.onboardUser = async (req, res) => {
  const { idNum, name, surname, typeOfUser, course, email } = req.body;

  if (!idNum || !name || !surname || !typeOfUser || !course || !email) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    //const userRef = db.collection('meetme').doc('users').collection('user').doc(idNum);
    const userRef = db
  .collection('meetme')
// this will be Student, Lecturer, or Advisor
  .doc(idNum);

    const userDoc = await userRef.get();

    if (userDoc.exists) {
      return res.status(400).json({ error: 'User already exists.' });
    }

    const otp = generateOtp();
    await userRef.set({
      idNum,
      name,
      surname,
      typeOfUser,
      course,
      email,
      otp: bcrypt.hashSync(otp, 10),
      otpExpiresAt: Date.now() + 600000,
      password: null
    });

    await sendOtpEmail(email, otp, idNum);
    res.status(200).json({ message: 'User onboarded. OTP sent.' });
  } catch (error) {
    console.error('Error onboarding:', error);
    res.status(500).json({ error: 'Server Error' });
  }
};

exports.verifyOtp = async (req, res) => {
  const { idNum, otp } = req.body;

  try {
    const userRef = db.collection('meetme').doc(idNum);
    const userDoc = await userRef.get();

    if (!userDoc.exists) return res.status(400).json({ error: 'User not found.' });
    
    const user = userDoc.data();
    const isOtpValid = user.otp && Date.now() < user.otpExpiresAt && bcrypt.compareSync(otp, user.otp);

    if (isOtpValid) {
        res.status(200).json({ message: 'OTP verified. Please set your password.' });
    } else {
        res.status(400).json({ error: 'Invalid or expired OTP.' });
    }          
  } catch (error) {
    console.error('Error during OTP validation:', error);
    res.status(500).json({ error: 'Failed to validate OTP.' });
  }
};

exports.setPassword = async (req, res) => {
  const { idNum, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('meetme').doc(idNum).update({
      password: hashedPassword,
      otp: null,
      otpExpiresAt: null
    });
    res.status(200).json({ message: 'Password set successfully.' });
  } catch (error) {
    //res.status(500).json({ error: 'Server Error' });
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Failed to change password.' });
  }
};

exports.login = async (req, res) => {
  const { idNum, password } = req.body;

  try {
    const userRef = db.collection('meetme').doc(idNum);
    const userDoc = await userRef.get();

    if (!userDoc.exists) return res.status(400).json({ error: 'User not found.' });

    const user = userDoc.data();
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) return res.status(400).json({ error: 'Invalid credentials.' });

    res.status(200).json({ message: 'Login successful.' });
  } catch (error) {
    res.status(500).json({ error: 'Server Error' });
  }
};

exports.getUserTypeById = async (req, res) => {
  const { idNum } = req.body;

  try {
    const userRef = db
      .collection('meetme')
      .doc(idNum);

    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const userData = userDoc.data();
    return res.status(200).json({ typeOfUser: userData.typeOfUser });
  } catch (error) {
    console.error('Error fetching user type:', error);
    return res.status(500).json({ error: 'Server Error' });
  }
};

exports.resendOtp = async (req, res) => {
  const { idNum } = req.body;

  if (!idNum) return res.status(400).json({ error: 'idNum is required.' });

  try {
    const userRef = db.collection('meetme').doc(idNum);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = userDoc.data();
    const newOtp = generateOtp();

    await userRef.update({
      otp: bcrypt.hashSync(newOtp, 10),
      otpExpiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes from now
    });

    await sendOtpEmail(user.email, newOtp, idNum);
    res.status(200).json({ message: 'OTP resent successfully.' });

  } catch (error) {
    console.error('Error resending OTP:', error);
    res.status(500).json({ error: 'Server Error' });
  }
};


exports.getUserById = async (req, res) => {
  const { idNum } = req.params;

  try {
    const userRef = db.collection('meetme').doc(idNum);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const userData = userDoc.data();
    // Optionally remove sensitive info
    delete userData.password;
    delete userData.otp;
    delete userData.otpExpiresAt;

    res.status(200).json({ user: userData });

  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Server Error' });
  }
};
