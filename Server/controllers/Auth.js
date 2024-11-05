const User = require("../models/User");
const OTP = require("../models/OTP");
const otpGenerator = require("otp-generator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const req = require("express/lib/request");
const res = require("express/lib/response");
require("dotenv").config();

//Send OTP
exports.sendOtp = async (req, res) => {
    try {
        //fetch email from req ki body
        const { email } = req.body;
        //check if user already exists
        const checkUserPresent = await User.findOne({ email });
        //if user exists then return a response
        if (checkUserPresent) {
            return res.status(401).json({
                success: false,
                message: "User already registered"
            })
        }
        //generate otp
        let otp = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false
        });
        console.log("OTP generated: ", otp);
        //check unique otp or not
        const result = await OTP.findOne({ otp: otp });
        while (result) {
            otp = otpGenerator.generate(6, {
                upperCaseAlphabets: false,
                lowerCaseAlphabets: false,
                specialChars: false
            });
            result = await OTP.findOne({ otp: otp });
        }
        const otpPayload = { email, otp };
        //create an entry for otp
        const otpBody = await OTP.create(otpPayload);
        console.log(otpBody);
        //return response successful
        res.status(200).json({
            success: true,
            message: "OTP sent successfully",
            otp
        })
    } catch (error) {
        console.log(error);
        return (res.status(500)).json({
            success: false,
            message: error.message
        })
    }
}

//Sign Up
exports.signup = async (req, res) => {
    try {
        //data fetch from req ki body
        const { firstName,
            lastName,
            email,
            password,
            confirmPassword,
            accountType,
            contactNumber,
            otp
        } = req.body;
        //validate karlo
        if (!firstName || !lastName || !email || !password || !confirmPassword || !otp) {
            return res.status(403).json({
                success: false,
                message: "All fields are required"
            });
        };
        //2 password match karlo
        if (password != confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "Password and Confirm Password does not match, Please try again"
            });
        };
        //check users already exists or not
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "User already exists with this email"
            });
        };

        //find most recent otp stored for the user
        const recentOtp = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1);
        console.log(recentOtp);
        //validate otp
        if (recentOtp.length == 0) {
            //OTP not found
            return res.status(400).json({
                success: false,
                message: "OTP not found"
            });
        } else if (otp != recentOtp) {
            return res.status(400).json({
                success: false,
                message: "Invalid OTP"
            });
        };

        //hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        //entry create in DB
        const profileDetails = await Profile.create({
            gender: null,
            dateOfBirth: null,
            about: null,
            contactNumber: null
        });
        const user = await User.create({
            firstName,
            lastName,
            email,
            contactNumber,
            password: hashedPassword,
            accountType,
            additionalDetails: profileDetails._id,
            image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`,
        });

        //return res
        return res.status(200).json({
            success: true,
            message: "User is registered successfully",
            user
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "User cannot be registered. Please try again",
        });
    }
}

//Login
exports.login = async (req, res) => {
    try {
        //get data from ki body
        const { email, password } = req.body;
        //validation data
        if (!email || !password) {
            return res.status(403).json({
                success: false,
                message: "All fields are required. Please try again",
            });
        }
        //user check exists or not
        const user = await User.findOne({ email }).populate("additionalDetails");
        if (!user) {
            return res.status(401).json({
                success: false,
                message: "User not found. Please register",
            });
        }
        //generate JWT, after password matching
        if (await bcrypt.compare(password, user.password)) {
            const payload = {
                email: user.email,
                id: user._id,
                role: user.role,
            }
            const token = jwt.sign(payload, process.env.JWT_SECRET, {
                expiresIn: "2h",
            });
            user.token = token;
            user.password = undefined;
            //create cookie and send response
            const options = {
                expires: new Date(Date.now) + 3 * 24 * 60 * 60 * 1000,
                httpOnly: true,
            }
            res.cookie("token", token, options).status(200).json({
                success: true,
                token,
                user,
                message: 'Logged in successfully',
            })
        } else {
            return res.status(401).json({
                success: false,
                message: 'Password is incorrect',
            });
        }
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: 'Login failure. Please try again. Please try again',
        })
    }
};

//Change Password
exports.changePassword = async (req, res) => {
    try {
        //get data from req body
        const userDetails = await User.findById(req.user.id);
        console.log("Change Password userDetails: ", userDetails);
        //get oldpassword, newpassword and confirmpassword
        const { oldPassword, newPassword, confirmNewPassword } = req.body;
        console.log("Old password: ", oldPassword, "New Password: ", newPassword, "Confirm New Password: ", confirmNewPassword);
        //validate old password
        const isPasswordMatch = await bcrypt.compare(
            oldPassword,
            userDetails.password
        );
        if (!isPasswordMatch) {
            //If old password does not match, return a 401 Unauthorized error
            return res.status(401).json({
                success: false,
                message: "Old password is incorrect",
            })
        }
        //Match new password and confirm new password
        if (newPassword != confirmNewPassword) {
            //If new password and confirm new password does not match, return a 400 Bad Request error
            return res.status(400).json({
                success: false,
                message: "Password and Confirm Password does not match",
            })
        }

        //update password in DB
        const encryptedPassword = await bcrypt.hash(newPassword, 10);
        const updatedUserDetails = await User.findByIdAndUpdate(
            req.user.id,
            { password: encryptedPassword },
            { new: true }
        );
        console.log("Updated User Details in password change auth: ", updatedUserDetails);
        //send mail- Password Updated
        try {
            const emailResponse = await mailSender(
                updatedUserDetails.email,
                "Password for your account has been updated",
                passwordUpdated(
                    updatedUserDetails.email,
                    `Password updated successfully for ${updatedUserDetails.firstName} ${updatedUserDetails.lastName}`
                )
            );
            console.log("Email sent successfully:", emailResponse.response);
        } catch (error) {
            // If there's an error sending the email, log the error and return a 500 (Internal Server Error) error
            console.error("Error occurred while sending email:", error);
            return res.status(500).json({
                success: false,
                message: "Error occurred while sending email",
                error: error.message,
            });
        }
        // Return success response
        return res
            .status(200)
            .json({ success: true, message: "Password updated successfully" });
    } catch (error) {
        // If there's an error updating the password, log the error and return a 500 (Internal Server Error) error
        console.error("Error occurred while updating password:", error);
        return res.status(500).json({
            success: false,
            message: "Error occurred while updating password",
            error: error.message,
        });
    }
}