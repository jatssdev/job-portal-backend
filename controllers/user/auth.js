const jwt = require('jsonwebtoken');
const User = require('../../models/Usermodel');
const ErrorHandler = require('../../middleware/errorHandler');
const sendMail = require('../../configs/nodeMailer');
const otpGenerator = require('otp-generator');

const validateFields = (fields) => {
    for (const [key, value] of Object.entries(fields)) {
        if (!value) {
            throw new ErrorHandler(`Field ${key} is required`, 400);
        }
    }
};

const RegisterUser = async (req, res, next) => {
    try {
        const { firstName, lastName, userName, email, password, confirmPassword, phoneNumber } = req.body;

        // Validate the incoming data
        validateFields({ firstName, lastName, userName, email, password, confirmPassword, phoneNumber });

        if (password !== confirmPassword) {
            throw new ErrorHandler('Passwords do not match', 400);
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            throw new ErrorHandler('Invalid email address', 400);
        }

        // Validate phone number format
        const phoneRegex = /^\d{10}$/;
        if (!phoneRegex.test(phoneNumber)) {
            throw new ErrorHandler('Invalid phone number', 400);
        }

        // Check if user already exists with the provided email, phone number, or username
        const existingUser = await User.findOne({ $or: [{ email }, { phoneNumber }, { userName }] });
        if (existingUser) {
            throw new ErrorHandler('User already exists', 409);
        }

        // Create a new user instance
        const newUser = new User({
            firstName,
            lastName,
            userName,
            email,
            password,
            phoneNumber
        });

        // Save the user to the database
        await newUser.save();

        setTimeout(() => {
            return res.status(201).json({ success: true, message: 'User registered successfully' });
        }, 3000)
    } catch (error) {
        next(error); // Pass errors to custom error handler
    }
};

const LoginUser = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        // Validate the incoming data
        validateFields({ email, password });
        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            throw new ErrorHandler('User not found', 404);
        }

        // Compare passwords
        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            throw new ErrorHandler('Invalid password', 401);
        }

        // Generate JWT token for authentication
        const token = jwt.sign({ userId: user._id }, 'jatinisbestcoderintheworld', { expiresIn: '15d' });

        return res.status(200)
            .cookie('token', token, { maxAge: 15 * 24 * 60 * 60000, httpOnly: true }) // Set cookie with token
            .json({ success: true, token, user: user }); // Send token in the response body

    } catch (error) {


        next(error); // Pass errors to custom error handler
    }
};

const otpStore = new Map();

const forgotPassword = async (req, res, next) => {
    try {
        const { email } = req.body;

        // Validate email
        if (!email) {
            throw new ErrorHandler('Email is required', 400);
        }

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            throw new ErrorHandler('User not found', 404);
        }

        // Generate OTP
        const otp = otpGenerator.generate(6, { digits: true, lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false });

        // Store OTP temporarily (in a real application, consider using a database with expiry)
        otpStore.set(email, otp);
        setTimeout(() => otpStore.delete(email), 10 * 60 * 1000); // OTP valid for 10 minutes

        // Send OTP to user's email
        await sendMail(email, 'Password Reset OTP', `Your OTP is: ${otp}`);

        res.status(200).json({ success: true, message: 'OTP sent to email' });
    } catch (error) {
        next(error);
    }
};

const verifyOtpAndResetPassword = async (req, res, next) => {
    try {
        const { email, otp, newPassword } = req.body;

        // Validate inputs
        validateFields({ email, otp, newPassword });

        // Check if OTP is valid
        const storedOtp = otpStore.get(email);
        if (!storedOtp || storedOtp !== otp) {
            throw new ErrorHandler('Invalid or expired OTP', 400);
        }

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            throw new ErrorHandler('User not found', 404);
        }

        // Hash new password and update user record
        user.password = newPassword;
        await user.save();

        // Remove OTP from store
        otpStore.delete(email);

        res.status(200).json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        next(error);
    }
};

const changePassword = async (req, res, next) => {
    try {
        const { currentPassword, newPassword } = req.body;

        // Validate inputs
        validateFields({ currentPassword, newPassword });

        // Get the user from the request (assumes user is authenticated and user object is attached to the request)
        const user = req.user;

        // Compare current password with the stored password
        const isPasswordValid = await user.comparePassword(currentPassword);
        if (!isPasswordValid) {
            throw new ErrorHandler('Current password is incorrect', 401);
        }

        // Set new password
        user.password = newPassword;

        // Save the updated user object
        await user.save();

        res.status(200).json({ success: true, message: 'Password changed successfully' });
    } catch (error) {
        next(error);
    }
};

const logoutUser = (req, res, next) => {

    try {
        return res.status(200)
            .cookie('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NjRkNzcyMWQ1ZWE5N2E1NWU3ZWFiZjIiLCJpYXQiOjE3MTYzODE1NjEsImV4cCI6MTcxNjM4NTE2MX0.eulrgOPD3Xpc043CtbP9LeyXmL7eQkRwZe-f0TYSMc4', { maxAge: 60 * 60000, httpOnly: true }) // Clear the token cookie
            .json({ success: true, token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NjRkNzcyMWQ1ZWE5N2E1NWU3ZWFiZjIiLCJpYXQiOjE3MTYzODE1NjEsImV4cCI6MTcxNjM4NTE2MX0.eulrgOPD3Xpc043CtbP9LeyXmL7eQkRwZe-f0TYSMc4', message: 'Logged out successfully' });
    } catch (error) {
        next(error); // Pass errors to custom error handler
    }
};

const checkAuth = (req, res, next) => {

    let { user } = req
    res.status(200).json({ success: true, user, message: 'user authenticated!' })
};

module.exports = { checkAuth, logoutUser, RegisterUser, changePassword, LoginUser, forgotPassword, verifyOtpAndResetPassword };
