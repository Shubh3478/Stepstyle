const User = require('../models/userdata');
const bcrypt = require('bcrypt');

const addUser = async (req, res) => {
    try {
        const { name, email, mobile, password, confirmpassword, profileImage } = req.body;

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: "Invalid email format."
            });
        }

        // Basic mobile number validation (10 digits)
        const mobileRegex = /^\d{10}$/;
        if (!mobileRegex.test(mobile)) {
            return res.status(400).json({
                success: false,
                message: "Invalid mobile number. It should be 10 digits."
            });
        }

        // Check for existing user
        const existing = await User.findOne({ email });
        if (existing) {
            return res.status(400).json({
                success: false,
                message: "User already exists."
            });
        }

        // Passwords match check
        if (password !== confirmpassword) {
            return res.status(400).json({
                success: false,
                message: "Passwords do not match."
            });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = await User.create({
            name,
            email,
            mobile,
            password:hashedPassword,
            profileImage
        });

        res.status(201).json({
            success: true,
            data: newUser,
            message: "User successfully created."
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).json({
            success: false,
            data: err.message,
            message: "Error while saving user."
        });
    }
};

module.exports = addUser;
