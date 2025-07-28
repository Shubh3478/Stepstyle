
const bcrypt = require('bcrypt');
const User = require('../models/userdata');

const updatePassword = async (req, res) => {
    try {
        const { email, oldPassword, newPassword } = req.body;

        // Find user by email
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        // Compare old password with hashed one
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        // console.log(user.password);
        // console.log(oldPassword);
        // console.log(isMatch)
        if (!isMatch) {
            return res.status(400).json({
                success: false,
                message: "Old password is incorrect"
            });
        }

        // Hash the new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update and save
        user.password = hashedNewPassword;
        await user.save();

        res.status(200).json({
            success: true,
            message: "Password updated successfully"
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            success: false,
            message: "Error updating password",
            error: err.message
        });
    }
};

module.exports = updatePassword;


