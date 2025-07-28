const User = require('../models/userdata');

const updateProfile = async (req, res) => {
  try {
    const { email, name, mobile, profileImage } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Conditionally update fields if they exist in request body
    if (name !== undefined) user.name = name;
    if (mobile !== undefined) user.mobile = mobile;
    if (profileImage !== undefined) user.profileImage = profileImage;

    await user.save();

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        name: user.name,
        email: user.email,
        mobile: user.mobile,
        profileImage: user.profileImage
      }
    });

  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

module.exports = updateProfile;
