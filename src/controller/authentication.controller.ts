import { Request, Response } from "express";
import { z } from "zod";
import { UserModel } from "../model/user.model";
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { generateOTP } from "../utils/utils";
import { OtpModel } from "../model/otp.model";

export const signupController = async (req: Request, res: Response) => {
    try {
        const schema = z.object({
            name: z.string().min(3, "Name Must me 3 characters"),
            email: z.string().email(),
            password: z
                .string()
                .min(6, "Password must be at least 6 characters long")
                .regex(/[A-Z]/, "Password must include at least one uppercase letter")
                .regex(/[a-z]/, "Password must include at least one lowercase letter")
                .regex(/[^A-Za-z0-9]/, "Password must include at least one special character")
        });

        // Validate input
        const { email, password, name } = schema.parse(req.body);;

        // Check if user already exists
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) throw new Error("User already exists");

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = await UserModel.create({
            name,
            email,
            password: hashedPassword,
        });

        // Trigger Kafka queue (TODO: implement producer)
        // await kafkaProducer.send({
        //   topic: "user.signup",
        //   messages: [{ value: JSON.stringify({ userId: newUser._id, email: newUser.email }) }],
        // });

        // Return success response
        return res.status(201).json({
            success: true,
            message: "User created successfully",
            userId: newUser._id,
        });

    } catch (error: unknown) {
        console.log(error);

        return res.status(500).json({
            success: false,
            error: error instanceof Error ? error.message : "Internal Server Error",
        });
    }
}

export const loginController = async (req: Request, res: Response) => {
    try {
        // Validation schema
        const schema = z.object({
            email: z.string().email(),
            password: z
                .string()
                .min(6, "Password must be at least 6 characters long")
                .regex(/[A-Z]/, "Password must include at least one uppercase letter")
                .regex(/[a-z]/, "Password must include at least one lowercase letter")
                .regex(/[^A-Za-z0-9]/, "Password must include at least one special character"),
        });

        // Validate input
        const { email, password } = schema.parse(req.body);

        // Check if user exists
        const existingUser = await UserModel.findOne({ email });
        if (!existingUser) throw new Error("User not found");

        // Verify password
        const hashed = existingUser.password;

        if (!hashed) throw new Error("Invalid credentials");

        const isVerified = await bcrypt.compare(password, hashed);
        if (!isVerified) throw new Error("Invalid credentials");

        // Generate JWT token (example)
        const token = jwt.sign(
            { userId: existingUser._id, email: existingUser.email },
            process.env.JWT_SECRET || "secret",
            { expiresIn: "1h" }
        );

        // // Set cookie (example)
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 3600 * 1000, // 1 hour
        });

        // Respond success
        return res.status(200).json({
            success: true,
            message: "Login successful",
            userId: existingUser._id,
            token: token
        });

    } catch (error: unknown) {
        return res.status(500).json({
            success: false,
            error: error instanceof Error ? error.message : "Internal Server Error",
        });
    }
};

export const forgetPassword = async (req: Request, res: Response) => {
    try {
        const schema = z.object({
            email: z.string().email(),
        });

        // Validate input
        const { email } = schema.parse(req.body);

        // Check if user exists
        const existingUser = await UserModel.findOne({ email });
        if (!existingUser) throw new Error("User not found");

        // generate the otp 
        const otp = generateOTP();

        if (!otp) throw new Error("Failed to generate OTP");

        //store the otp in otp table 
        const otpStored = await OtpModel.create({
            otp: otp,
            email: existingUser.email,
            userId: existingUser._id,
            expiresAt: new Date(Date.now() + 10 * 60 * 1000)
        })

        if (!otpStored) throw new Error("Failed to store otp");

        // Set a cookie to indicate OTP is verified
        res.cookie("otpSent", "true", {
            httpOnly: true, // frontend cannot access JS
            secure: process.env.NODE_ENV === "production", // HTTPS only in prod
            maxAge: 10 * 60 * 1000, // 10 minutes
            sameSite: "lax",
        });

        res.cookie("otpEmail", email, {
            httpOnly: true, // frontend cannot access JS
            secure: process.env.NODE_ENV === "production", // HTTPS only in prod
            maxAge: 10 * 60 * 1000, // 10 minutes
            sameSite: "lax",
        })
        // send the otp to the user via mail
        console.log(otp);

        return res.status(200).json({
            success: true,
            message: "OTP Sent to email"
        })
    } catch (error: unknown) {
        return res.status(500).json({
            success: false,
            error: error instanceof Error ? error.message : "Internal Server Error",
        });
    }
}

export const verifyOtp = async (req: Request, res: Response) => {
    try {
        const schema = z.object({
            otp: z.string().length(6, "OTP must be 6 digits"),
            email: z.string().email(),
        });

        const { otp, email } = schema.parse(req.body);

        // Find most recent OTP
        const storedOtp = await OtpModel.findOne({ email }).sort({ createdAt: -1 });

        if (!storedOtp) throw new Error("No OTP found. Please generate a new one.");
        if (storedOtp.expiresAt && storedOtp.expiresAt < new Date()) {
            throw new Error("OTP has expired. Please generate a new one.");
        }
        if (storedOtp.otp !== otp) throw new Error("Invalid OTP. Please try again.");

        // Optional: delete OTP after verification
        await OtpModel.deleteOne({ _id: storedOtp._id });

        // Set a cookie to indicate OTP is verified
        res.cookie("otpVerified", "true", {
            httpOnly: true, // frontend cannot access JS
            secure: process.env.NODE_ENV === "production", // HTTPS only in prod
            maxAge: 10 * 60 * 1000, // 10 minutes
            sameSite: "lax",
        });

        // Set a 10-minute password reset window cookie
        res.cookie("passwordResetAllowed", "true", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 10 * 60 * 1000, // 10 minutes
            sameSite: "lax",
        });

        res.cookie("email", email, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 10 * 60 * 1000, // 10 minutes
            sameSite: "lax",
        });

        res.clearCookie('otpSent');

        return res.status(200).json({
            success: true,
            message: "OTP verified successfully",
        });
    } catch (error: unknown) {
        return res.status(500).json({
            success: false,
            error: error instanceof Error ? error.message : "Internal Server Error",
        });
    }
};

export const resetPassword = async (req: Request, res: Response) => {
    try {
        const schema = z.object({
            email: z.string().email(),
            newPassword: z
                .string()
                .min(6, "Password must be at least 6 characters long")
                .regex(/[A-Z]/, "Password must include at least one uppercase letter")
                .regex(/[a-z]/, "Password must include at least one lowercase letter")
                .regex(/[^A-Za-z0-9]/, "Password must include at least one special character")
        });

        const { email, newPassword } = schema.parse(req.body);

        // Check if password reset window is still valid
        if (req.cookies.passwordResetAllowed !== "true") {
            throw new Error("Password reset session expired. Please re-verify OTP.");
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10)
        // Update password
        await UserModel.updateOne(
            { email },
            { $set: { password: hashedPassword } }
        );

        // Clear the reset window cookie
        res.clearCookie("passwordResetAllowed");
        res.clearCookie("otpVerified")

        //Send mail confirmation

        return res.status(200).json({
            success: true,
            message: "Password reset successfully",
        });
    } catch (error: unknown) {

        return res.status(500).json({
            success: false,
            error: error instanceof Error ? error.message : "Internal Server Error",
        });
    }
};

export const changePassword = async (req: Request, res: Response) => {
    try {
        const schema = z.object({
            email: z.string().email(),
            oldPassword: z
                .string()
                .min(6, "Password must be at least 6 characters long")
                .regex(/[A-Z]/, "Password must include at least one uppercase letter")
                .regex(/[a-z]/, "Password must include at least one lowercase letter")
                .regex(/[^A-Za-z0-9]/, "Password must include at least one special character"),
            newPassword: z
                .string()
                .min(6, "Password must be at least 6 characters long")
                .regex(/[A-Z]/, "Password must include at least one uppercase letter")
                .regex(/[a-z]/, "Password must include at least one lowercase letter")
                .regex(/[^A-Za-z0-9]/, "Password must include at least one special character")
        })

        const { email, newPassword, oldPassword } = schema.parse(req.body);

        const existingUser = await UserModel.findOne({ email });

        if (!existingUser) throw new Error("User not found");

        if (oldPassword === newPassword) throw new Error('Old and new password should be different')

        if (!existingUser.password) throw new Error('Account maybe connected with the github')

        const isVerified = await bcrypt.compare(oldPassword, existingUser.password);

        if (!isVerified) throw new Error('Invalid Old Password');

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await existingUser.updateOne({ $set: { password: hashedPassword } });

        return res.status(200).json({
            success: true,
            message: "Password changed successfully",
        });
    } catch (error: unknown) {
        return res.status(500).json({
            success: false,
            error: error instanceof Error ? error.message : "Internal Server Error",
        });
    }
}