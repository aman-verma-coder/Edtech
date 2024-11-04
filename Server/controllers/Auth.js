const User = require("../models/User");
const OTP = require("../models/OTP");
const otpGenerator = require("otp-generator");
const req = require("express/lib/request");
const res = require("express/lib/response");

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
        })
    }
    //2 password match karlo
    if (password != confirmPassword) {
        return res.status(400).json({
            success: false,
            message: "Password and Confirm Password does not match, Please try again"
        })
    }
    //check users already exists or not
    const existingUser = await User.findOne({ email })
    if (existingUser) {
        return res.status(400).json({
            success: false,
            message: "User already exists with this email"
        })
    }

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
    }

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
    });

    //return res
}

//Login

//Change Password