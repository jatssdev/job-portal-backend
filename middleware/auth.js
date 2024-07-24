const jwt = require('jsonwebtoken');
const User = require('../models/Usermodel');
const ErrorHandler = require('./errorHandler'); // Import the ErrorHandler middleware
const { generateAccessToken } = require('../controllers/user/auth');

const authenticateUser = async (req, res, next) => {
    const accessToken = req.cookies.accessToken;
    const refreshToken = req.cookies.refreshToken;

    if (!accessToken) {
        return res.status(401).json({ message: 'Access token required' });
    }

    try {
        // Verify access token
        const decoded = jwt.verify(accessToken, 'tirthisagoodboy');
        req.user = decoded;

        next();
    } catch (err) {
        console.log('err', err.message)

        if (err.name === 'TokenExpiredError' && refreshToken) {
            try {
                // Verify refresh token
                const decodedRefresh = jwt.verify(refreshToken, 'tirthisnotagoodboy');

                const user = await User.findById(decodedRefresh.id);

                // Generate new access token
                const newAccessToken = generateAccessToken(user);

                // Set new access token cookie
                res.cookie('accessToken', newAccessToken, {
                    maxAge: 15 * 60 * 1000, // 15 minutes
                    httpOnly: true,

                });

                req.user = user;
                next();
            } catch (refreshErr) {
                return res.status(403).json({ message: 'Invalid refresh token' });
            }
        } else {
            return res.status(403).json({ message: 'Invalid  token' });
        }
    }
};
module.exports = { authenticateUser };