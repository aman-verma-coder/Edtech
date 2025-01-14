const req = require("express/lib/request");
const User = require("../models/User");
const mailSender = require("../utils/mailSender");
const res = require("express/lib/response");
//Reset Password Token
exports.resetPasswordToken = async (req, res) => {
    //get email from req body
    const email = req.body.email;
    //check user for this email, email validation
    const user = await User.findOne({ email: email });
    if (!user) {
        return res.status.json({
            success: false,
            message: 'You email is not registered with us',
        })
    }
    //generate token
    const token = crypto.randomUUID();
    //update user by adding token and expiration time
    const updatedDetails = await User.findOneAndUpdate(
        { email: email },
        {
            token: token,
            resetPasswordExpires: Date.now() + 5 * 60 * 1000
        },
        { new: true });
    //create url
    const url = `http://localhostL:3000/update-password/${token}`;
    //send email containing url
    await mailSender(email,"Password Reset Link",`Password Reset Link: ${url}``);
    //return response
    return res.json
}

//Reset Password