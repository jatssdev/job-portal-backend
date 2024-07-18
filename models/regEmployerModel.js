const mongoose = require('mongoose');

const EmployerSchema = mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  phone: {
    type: String,
    required: true,
  },
  organizationName: {
    type: String,
    required: true,
  },
  termsAccepted: {
    type: Boolean,
    required: true,
  }
});

const employerModel = mongoose.model('Employer', EmployerSchema);

module.exports = employerModel
