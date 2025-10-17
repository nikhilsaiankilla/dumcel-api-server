import express from "express";
import {
    changePassword,
    deleteAccountController,
    forgetPassword,
    getUserController,
    githubLoginController,
    loginController,
    resetPassword,
    signupController,
    verifyOtp
} from "../controller/authentication.controller";
import { authMiddleware } from "../middleware/auth.middleware";

const router = express.Router();

// Signup
router.post("/signup", signupController);

// GitHub OAuth connect
router.get("/github/login", (req, res) => {
    const secrets = global.secrets;

    if (!secrets?.github_client_id || !secrets?.github_client_secret) {
        throw new Error("Auth Secrets are missing");
    }

    const redirectUri = "http://localhost:3000/connecting";
    const clientId = secrets.github_client_id;
    const scope = "repo,user:email"; // ask for repo access

    const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}`;

    res.send({ redirectUri: githubAuthUrl });
});

// GitHub OAuth callback
router.get("/github/callback", githubLoginController);

// Authentication routes
router.post("/login", loginController);
router.post("/forget-password", forgetPassword);
router.post("/verify-otp", verifyOtp);
router.post("/reset-password", resetPassword);

// Account management (protected routes)
router.delete("/delete/account", authMiddleware, deleteAccountController);
router.post("/change-password", authMiddleware, changePassword);

// get user
router.get('/get-user', authMiddleware, getUserController)

export const authenticationRouter = router;
