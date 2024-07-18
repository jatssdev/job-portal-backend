const jwt = require('jsonwebtoken');
const User = require('../models/Usermodel');
const ErrorHandler = require('./errorHandler'); // Import the ErrorHandler middleware

const authenticateUser = async (req, res, next) => {
    try {
        // Extract token from request headers
        const token = req.cookies.token

        // Check if token is provided=1
        if (!token) {
            throw new ErrorHandler('Token is required', 401);
        }
        // Verify token
        const decoded = jwt.verify(token, 'jatinisbestcoderintheworld');
        // Find user by id from decoded token
        const user = await User.findById(decoded.userId);
        if (!user) {
            throw new ErrorHandler('User not found', 404);
        }
        // Attach user object to request for further processing
        req.user = user;
        // Proceed to next middleware or route handler
        next();
    } catch (error) {
        console.log(error.message)
        next(new ErrorHandler(error.message, 501)); // Pass errors to custom error handler
    }
};

module.exports = { authenticateUser };