import { Request, Response } from "express";
import { z } from "zod";
import { UserModel } from "../model/user.model";
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { generateOTP } from "../utils/utils";
import { OtpModel } from "../model/otp.model";
import { TokenModel } from "../model/tokens.model";
import { AuthenticatedRequest } from "../middleware/auth.middleware";
import { ProjectModel } from "../model/project.model";
import { DeploymentModel } from "../model/deployment.model";
import mongoose from "mongoose";

export const githubLoginController = async (req: Request, res: Response) => {
    try {
        const secrets = global.secrets;
        if (!secrets?.github_client_id || !secrets?.github_client_secret) {
            throw new Error("GitHub OAuth secrets missing");
        }

        const { code } = req.query;
        if (!code) return res.status(400).send("Missing authorization code");

        // Exchange code → access token
        const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
            },
            body: JSON.stringify({
                client_id: secrets.github_client_id,
                client_secret: secrets.github_client_secret,
                code,
            }),
        });

        const tokenData = await tokenRes.json();
        const accessToken = tokenData.access_token;
        if (!accessToken) return res.status(500).send("GitHub token exchange failed");

        // Get GitHub user profile + email
        const [userRes, emailRes] = await Promise.all([
            fetch("https://api.github.com/user", {
                headers: { Authorization: `Bearer ${accessToken}` },
            }),
            fetch("https://api.github.com/user/emails", {
                headers: { Authorization: `Bearer ${accessToken}` },
            }),
        ]);

        const ghUser = await userRes.json();
        const ghEmails = await emailRes.json();
        const primaryEmail = ghEmails.find((e: any) => e.primary)?.email;

        // Use githubId or email to find user
        let user =
            (primaryEmail && (await UserModel.findOne({ email: primaryEmail }))) ||
            (await UserModel.findOne({ githubId: ghUser.id }));

        // If not found, create new user
        if (!user) {
            user = await UserModel.create({
                name: ghUser.name || ghUser.login,
                email: primaryEmail || `${ghUser.login}@github.nouser`,
                githubId: ghUser.id,
                photo: ghUser.avatar_url,
            });
        } else {
            // Update missing GitHub fields if necessary
            if (!user.githubId) {
                user.githubId = ghUser.id;
                await user.save();
            }
        }

        // Issue JWT
        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET || "secret",
            { expiresIn: "1h" }
        );

        // // Set cookie (example)
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 3600 * 1000, // 1 hour
        });

        // Redirect to frontend with token
        const redirectUrl = `${process.env.FRONTEND_URL}/auth/github?token=${token}`;
        return res.redirect(redirectUrl);

    } catch (err) {
        console.error("GitHub login error:", err);
        res.status(500).send("GitHub login failed");
    }
};

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

        //send otp via mail

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

export const deleteAccountController = async (req: AuthenticatedRequest, res: Response) => {
    const session = await mongoose.startSession();

    try {
        const userId = req.user?.userId;
        if (!userId) {
            return res.status(401).json({ success: false, message: "Unauthenticated user" });
        }

        const user = await UserModel.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        session.startTransaction();

        await Promise.all([
            ProjectModel.deleteMany({ userId }).session(session),
            TokenModel.deleteMany({ userId }).session(session),
            DeploymentModel.deleteMany({ userId }).session(session),
            OtpModel.deleteMany({ userId }).session(session),
            UserModel.deleteOne({ _id: userId }).session(session),
        ]);

        await session.commitTransaction();
        session.endSession();

        return res.status(200).json({
            success: true,
            message: "Account and all related data deleted successfully.",
        });
    } catch (error: unknown) {
        await session.abortTransaction();
        session.endSession();
        console.error("Error deleting account:", error);

        return res.status(500).json({
            success: false,
            message: "Failed to delete account",
            error: error instanceof Error ? error.message : 'Internal server error',
        });
    }
};

export const getUserController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        if (!userId) {
            return res.status(401).json({ success: false, message: "Unauthenticated user" });
        }

        const user = await UserModel.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        return res.status(200).json({
            success: true,
            message: "User retrieved successfully",
            data: user,
        });
    } catch (error: unknown) {
        console.error("Error fetching user:", error);
        return res.status(500).json({
            success: false,
            message: "Failed to fetch user",
            error: error instanceof Error ? error.message : 'Internal server error',
        });
    }
}