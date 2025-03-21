import express from 'express';
import { getProfile, login, logout, register, resetPassword, sendPasswordResetOtp, sendVerifyOtp, updateProfile, verifyOtp } from '../controllers/user.controllers.js';
import { userAuth } from '../middlewares/userAuth.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login)
router.post('/logout', logout)
router.post('/verify-otp', userAuth, sendVerifyOtp)
router.post('/verify-account', userAuth, verifyOtp)
router.post('/reset-password-otp', userAuth, sendPasswordResetOtp)
router.post('/reset-password', userAuth, resetPassword)
router.post('/profile', userAuth, updateProfile)
router.get('/profile', userAuth, getProfile)

export default router;