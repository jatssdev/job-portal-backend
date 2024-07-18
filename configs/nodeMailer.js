// mailer.js
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail', // Use your email service
    auth: {
        user: 'j3tinr3val@gmail.com',
        pass: 'fofq sfuf rnrt zjzo'
    }
});

const sendMail = async (to, subject, text) => {
    const mailOptions = {
        from: 'j3tinr3val@gmail.com',
        to,
        subject,
        text
    };

    await transporter.sendMail(mailOptions);
};

module.exports = sendMail;
