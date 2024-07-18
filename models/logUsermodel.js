const mongoose = require('mongoose')
let logUserSchema = mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
})
let logUserModel = mongoose.model('users', logUserSchema)

module.exports = logUserModel