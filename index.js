const express = require('express');
const cors = require('cors');
const { mongodbCon } = require('./configs/dbCon');
const userRoutes = require('./routes/userRoutes');
const employRouter = require('./routes/emploterRouter');
const cookies = require('cookie-parser');
let dotenv = require('dotenv')
dotenv.config()
// Create an instance of Express
const app = express();

// extended: true allows for rich objects and arrays to be encoded into the URL-encoded format
app.use(express.urlencoded({ extended: true }))

// Use CORS middleware to allow cross-origin requests
app.use(cors());

// Use middleware to parse JSON bodies
app.use(express.json());

// Use cookie-parser middleware to handle cookies
app.use(cookies());

// Define the route for user-related API requests
app.use('/api/user', userRoutes);

// Define the route for employer-related API requests
app.use('/api/employer', employRouter);

// Error handling middleware
app.use((err, req, res, next) => {
    // Set default status code and status if not already set
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    // Send the error response
    res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
        success: false
    });
});

// Connect to MongoDB using the provided connection string
// mongodbCon('mongodb+srv://jobPortal:jobPortal@database.ozcdemr.mongodb.net/?retryWrites=true&w=majority&appName=database');
mongodbCon(process.env.MONGOURI);

// Start the server and listen on port 5500
app.listen(process.env.PORT || 5500, () => console.log('Server is running on port 5500'));
