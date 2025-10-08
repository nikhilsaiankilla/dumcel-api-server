import express from "express";
import { changePassword, forgetPassword, loginController, resetPassword, signupController, verifyOtp } from "../controller/authentication.controller";
import { authMiddleware } from "../middleware/auth.middleware";

const router = express.Router();

router.post('/signup', signupController);

router.post('/login', loginController);

router.post('/forget-password', forgetPassword);

router.post('/verify-otp', verifyOtp);

router.post('/reset-password', resetPassword);

router.post('/change-password', authMiddleware, changePassword);

export const authenticationRouter = router;
