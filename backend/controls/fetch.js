

const User = require('../models/userdata');
const bcrypt = require('bcrypt'); // Uncomment if using hashed passwords

const getUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required"
            });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        // If you're using hashed passwords with bcrypt:
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        // If passwords are stored in plain text (not recommended)
        // if (password !== user.password) {
        //     return res.status(401).json({
        //         success: false,
        //         message: "Invalid email or password"
        //     });
        // }

        // Respond with user details, including profile image
        return res.status(200).json({
            success: true,
            message: "User exists",
            user: {
                name: user.name,
                email: user.email,
                mobile: user.mobile,
                profileImage: user.profileImage // Add the profile image
            }
        });

    } catch (err) {
        console.error("Error in getUser:", err);
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
};

module.exports = getUser;
