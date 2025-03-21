import jwt from 'jsonwebtoken';

export const userAuth = async (req, res, next) => {
    const token = req.cookies.token;
    console.log(token)

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'User not authenticated'
        });
    };

    try {
        const decodedData = jwt.verify(token, process.env.JWT_SECRET);
        console.log(decodedData)
        req.userId = decodedData?.id;
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: 'User not authenticated'
        });
    }
}