const bcrypt = require('bcrypt');
const User = require('../models/userdata')

const resetPassword = async (req, res) => {
    try {
        const { token, password } = req.body;

        const user = await User.findOne({
            resetToken: token,
            tokenExpiration: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid or expired token",
            });
        }

        User.password = await bcrypt.hash(password, 10);
        User.resetToken = undefined;
        User.tokenExpiration = undefined;
        await user.save();

        return res.status(200).json({
            success: true,
            message: "Password reset successfully",
        });
    } catch (err) {
        console.log(err)
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};

module.exports = resetPassword;
