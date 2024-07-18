const express = require('express')
const { employerReg } = require('../controllers/employer/employerController')

const employRouter = express.Router()

employRouter.post('/register', employerReg)

module.exports = employRouter