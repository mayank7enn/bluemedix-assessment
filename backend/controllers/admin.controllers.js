import User from '../models/user.js';
import bcrypt from 'bcryptjs';

export const createUser = async (req, res) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
        return res.status(400).json({ message: 'All fields are required' });
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

        const user = await User.create({ name, email, password: hashedPassword, role});

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            user,
        });
    } catch (err) {
        return res.status(500).json({
            success: false,
            message: err.message
        });
    }
}

export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find({});
        res.status(200).json({
            success: true,
            users
        });
    } catch (err) {
        return res.status(500).json({
            success: false,
            message: err.message
        });
    }
}

export const getUserById = async (req, res) => {
    const { id } = req.params;
    try {
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        res.status(200).json({
            success: true,
            user
        });
    }catch(err) {
        return res.status(500).json({
            success: false,
            message: err.message
        });
    }
}

export const updateUser = async (req, res) => {
    const { id } = req.params;
    const { name, role } = req.body;
    if (!name || !role) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        user.name = name;
        user.role = role;

        await user.save();

        res.status(200).json({
            success: true,
            message: 'User updated successfully',
            user
        });
    } catch (err) {
        return res.status(500).json({
            success: false,
            message: err.message
        });
    }
}

export const deleteUser = async (req, res) => {
    const { id } = req.params;
    try {
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        await user.remove();
        return res.status(200).json({
            success: true,
            message: 'User deleted successfully'
        });
    }catch(err) {
        return res.status(500).json({
            success: false,
            message: err.message
        });
    }
}