import User from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
// import nodemailer from 'nodemailer';
import { transporter } from '../config/mailer.js';

const sendTokenCookie = (res, token) => {
    const cookieOptions = {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
    };
    if (process.env.NODE_ENV === 'production') {
        cookieOptions.secure = true;
        cookieOptions.sameSite = 'none';
    } else {
        cookieOptions.sameSite = 'strict';
    }
    res.cookie('token', token, cookieOptions);
};

export const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            success: false,
            message: 'All fields are required'
        });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User already exists'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = await User.create({ name, email, password: hashedPassword, role: 'customer' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

        res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
        });

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user,
            token,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Please provide both email and password'
        });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found with this email'
            });
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if (!isPasswordCorrect) {
            return res.status(400).json({
                success: false,
                message: 'Invalid credentials'
            });
        }


        const token = jwt.sign(
            { id: user._id, role: user.role || 'customer' }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
        });

        res.status(200).json({
            success: true,
            message: 'User logged in successfully',
            user: {
                name: user.name,
                email: user.email,
                role: user.role || 'customer',
            },
            token,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
};

export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000,
        });
        res.status(200).json({
            success: true,
            message: 'User logged out successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
}

export const sendVerifyOtp = async (req, res) => {
    try{
        const {email} = req.body;
        console.log(req.body)
        const user = await User.findOne({ email });
        console.log(user)
        if(user.isAccountVerified){
            return res.status(400).json({
                success: false,
                message: 'Account already verified'
            });
        }
        
        const otp = Math.floor(1000 + Math.random() * 9000);
        user.verifyOtp = otp.toString();
        user.verifyOtpExpiredAt = Date.now() + 10 * 60 * 1000;

        await user.save();
        console.log(user)

        const mailOptions = {
            from: process.env.SMTP_USERNAME,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Welcome to our authentication system, your account verification OTP is: ${otp}`, 
        }
        await transporter.sendMail(mailOptions);
        console.log(`Email sent to ${email}`);
        res.status(200).json({
            success: true,
            message: 'OTP sent successfully'
        })
    }catch(error){
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
}


export const verifyOtp = async (req, res) => {
    const { email, otp } = req.body;
    console.log(req.body)

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.verifyOtp.toString() !== otp.toString()) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        if (user.verifyOtpExpiredAt < Date.now()) {
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        // Mark the account as verified
        user.isAccountVerified = true;
        user.verifyOtp = '';  // Instead of null
        user.verifyOtpExpiredAt = 0;
        

        await user.save();

        res.status(200).json({
            success: true,
            message: 'Email verified successfully'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
};

export const sendPasswordResetOtp = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const otp = Math.floor(1000 + Math.random() * 9000);

        user.resetOtp = otp.toString();

        user.resetOtpExpiredAt = Date.now() + 10 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Welcome to our authentication system, your account's Password change OTP is: ${otp}`, 
        }

        await transporter.sendMail(mailOptions);
        console.log(`Email sent to ${email}`);
        res.status(200).json({
            success: true,
            message: 'OTP sent successfully'
        })
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
}

export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.resetOtp.toString() !== otp.toString()) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        if (user.resetOtpExpiredAt < Date.now()) {
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        // Generate new JWT token after password reset
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

        // Set the token in HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 24 * 60 * 60 * 1000,
        });

        res.status(200).json({
            success: true,
            message: 'Password reset successfully',
            token: token, // Return the new token in the response
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
}

export const getProfile = async (req, res) => {
    try {
        const userId = req.userId; // Assuming you get `userId` from authentication middleware
        console.log(userId)
        const user = await User.findById(userId).select("-password"); // Exclude password

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        return res.status(200).json({
            success: true,
            user: {
                name: user.name,
                email: user.email,
                role: user.role, // Default role if not found
            },
        });
    } catch (error) {
        console.error("Error fetching profile:", error);
        return res.status(500).json({ success: false, message: "Server error" });
    }
};

export const updateProfile = async (req, res) => {
    try {
        const userId = req.userId; // Assuming you get `userId` from authentication middleware

        const { name } = req.body;

        // Update user details
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { name, updatedAt: Date.now() },
            { new: true, runValidators: true }
        ).select("-password"); // Exclude password from response

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        return res.status(200).json({
            success: true,
            message: "Profile updated successfully",
            profile: updatedUser,
        });
    } catch (error) {
        console.error("Error updating profile:", error);
        return res.status(500).json({ success: false, message: "Server error" });
    }
};