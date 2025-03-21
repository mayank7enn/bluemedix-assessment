import User from '../models/user.js'; // Adjust the path as needed

export const adminAuth = async (req, res, next) => {
    try {
        // Ensure userAuth middleware has already set req.userId
        if (!req.userId) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Not authenticated.'
            });
        }

        // Fetch user from the database
        const user = await User.findById(req.userId);

        if (!user || user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admins only.'
            });
        }

        next(); // Proceed if user is admin
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};
