import { Response } from "express";
import { AuthenticatedRequest } from "../middleware/auth.middleware";
import { TokenModel } from "../model/tokens.model";
import jwt from 'jsonwebtoken'
import { UserModel } from "../model/user.model";

export const githubRepoConnectController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const secrets = global.secrets;
        if (!secrets?.github_client_id || !secrets?.github_client_secret) {
            throw new Error("GitHub OAuth secrets missing");
        }

        const { code, state } = req.query;
        if (!code) return res.status(400).send("Missing code");

        // Decode JWT user from state (added during repo connect)
        let userId: string | undefined;
        try {
            const decoded: any = jwt.verify(state as string, process.env.JWT_SECRET || "secret");
            userId = decoded.userId;
        } catch {
            return res.status(400).send("Invalid state");
        }

        // Exchange code → access token with repo scope
        const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
            method: "POST",
            headers: { "Content-Type": "application/json", Accept: "application/json" },
            body: JSON.stringify({
                client_id: secrets.github_client_id,
                client_secret: secrets.github_client_secret,
                code,
            }),
        });

        const tokenData = await tokenRes.json();
        const accessToken = tokenData.access_token;
        if (!accessToken) return res.status(500).send("GitHub token exchange failed");

        // Save or update token
        await TokenModel.findOneAndUpdate(
            { user: userId, provider: "github" },
            { accessToken },
            { upsert: true, new: true }
        );

        await UserModel.findByIdAndUpdate(userId, { isGitConnected: true }, { new: true })

        return res.redirect(`${process.env.FRONTEND_URL}/dashboard?github=connected`);
    } catch (err) {
        console.error("GitHub repo connect error:", err);
        res.status(500).send("GitHub repo connection failed");
    }
};

export const githubGetReposController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        if (!userId) return res.status(401).send("Unauthorized");

        const tokenDoc = await TokenModel.findOne({ user: userId, provider: "github" });
        if (!tokenDoc?.accessToken) return res.status(400).send("GitHub not connected");

        // Fetch repositories
        const reposRes = await fetch("https://api.github.com/user/repos", {
            headers: { Authorization: `Bearer ${tokenDoc.accessToken}` },
        });

        const repos = await reposRes.json();
        return res.status(200).json(repos);
    } catch (err) {
        console.error("GitHub repo fetch error:", err);
        res.status(500).send("Failed to fetch GitHub repos");
    }
};
