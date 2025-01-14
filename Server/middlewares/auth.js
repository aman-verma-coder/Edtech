const jwt = require("jsonwebtoken");
require("dotenv").config();
const User = require("../models/User");
const req = require("express/lib/request");
const res = require("express/lib/response");
//auth
exports.auth = async (req, res, next) => {
    try {
        //extract token
        const token = req.cookies.token || req.body.token || req.header("Authorisation").replace("Bearer", "");
        //if token missing then return response
        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Token is missing",
            });
        }
        //verify the token
        try {
            const decode = await jwt.verify(token.procees.enc.JWT_SECRET);
            console.log(decode);
            req.user = decode;
        } catch (error) {
            //verification issue
            return res.status(401).json({
                success: false,
                message: "Invalid Token",
            });
        }
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Something went wrong while validating the token",
        })
    }
}

//isStudent
exports.isStudent = async (req, res, next) => {
    try {
        if (req.user.accountType != "Student") {
            return (res.status(401).json({
                success: false,
                message: "This is a protected route for students only",
            }))
        }
        next();
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "User role cannot be verified. Please try again later",
        });
    }
}
//isInstructor
exports.isStudent = async (req, res, next) => {
    try {
        if (req.user.accountType != "Instructor") {
            return (res.status(401).json({
                success: false,
                message: "This is a protected route for instructor only",
            }))
        }
        next();
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "User role cannot be verified. Please try again later",
        });
    }
}

//isAdmin
exports.isStudent = async (req, res, next) => {
    try {
        if (req.user.accountType != "Admin") {
            return (res.status(401).json({
                success: false,
                message: "This is a protected route for admin only",
            }))
        }
        next();
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "User role cannot be verified. Please try again later",
        });
    }
}