const User = require('../models/userdata');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config(); 

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'mhakalshiv8000@gmail.com',
        pass: process.env.EMAIL_PASSWORD,
    },
    tls: {
        rejectUnauthorized: false,
    },
});

const forgetPassword = async (req, res) => {
    try {
        const { email } = req.body;

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: "User does not exist",
            });
        }

        // Generate token and store in user
        const token = crypto.randomBytes(32).toString('hex');
        user.resetToken = token;
        user.tokenExpiration = Date.now() + 3600000; // 1 hour
        await user.save();

        // Create reset link with token
        const resetLink = `https://stepstyles.onrender.com/reset-password.html?token=${token}`;

        const mailOptions = {
            from: '"Stepstyle "<mhakalshiv8000@gmail.com>',
            to: email,
            subject: "Password Reset Request",
            html: `
                <h3>Password Reset Request</h3>
                <p>Hi,</p>
                <p>You requested a password reset. Please click the link below to reset your password:</p>
                <a href="${resetLink}" target="_blank">Reset Your Password</a>
                <p><strong>Important:</strong> The link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
                <br>
                <p>Best regards,</p>
                <p>StepStyle Team</p>
            `,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending email:', error);
                return res.status(500).json({
                    success: false,
                    message: 'Email failed to send',
                });
            }

            res.status(200).json({
                success: true,
                message: 'Password reset email sent successfully.',
            });
        });

    } catch (err) {
        console.error("Forget password error:", err);
        res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

module.exports = forgetPassword;
