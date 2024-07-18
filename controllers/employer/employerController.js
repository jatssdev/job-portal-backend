const bcrypt = require('bcryptjs');
const employerModel = require('../../models/regEmployerModel')

// Define the employer registration function
const employerReg = async (req, res) => {
  // Destructure the request body to extract required fields
  const { firstName, lastName, username, email, password, phone, organizationName, termsAccepted } = req.body;

  // Basic validation to check if all fields are present
  if (!firstName || !lastName || !username || !email || !password || !phone || !organizationName || !termsAccepted) {
    return res.status(400).json({ msg: 'Please enter all fields' });
  }

  try {
    // Check if an employer with the given email already exists
    let employer = await employerModel.findOne({ email });
    console.log(employer);
    if (employer) {
      return res.status(400).json({ msg: 'Employer already exists' });
    }

    // Create a new employer instance with the provided data
    employer = new employerModel({
      firstName,
      lastName,
      username,
      email,
      password,
      phone,
      organizationName,
      termsAccepted,
    });

    // Encrypt the employer's password before saving to the database
    const salt = await bcrypt.genSalt(10);
    employer.password = await bcrypt.hash(password, salt);

    // Save the new employer to the database
    await employer.save();

    // Send a success response
    res.status(201).json({ msg: 'Employer registered successfully' });
  } catch (err) {
    // Log any errors and send a server error response
    console.error(err.message);
    res.status(500).send('Server error');
  }
};

module.exports = { employerReg }
