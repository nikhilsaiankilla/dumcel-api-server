// utils/connectDb.ts
import mongoose from "mongoose";

export async function connectDb(): Promise<void> {
    const secrets = global.secrets;

    if (mongoose.connection.readyState === 1) {
        console.log("Already connected to MongoDB.");
        return;
    }

    try {
        if (!secrets?.mongoDb_uri) {
            throw new Error("MongoDB URI is not defined in secrets");
        }

        await mongoose.connect(secrets.mongoDb_uri);
        console.log("Successfully connected to MongoDB!");
    } catch (err) {
        console.error("MongoDB connection error:", err);
        process.exit(1);
    }
}

// Optional: Close the connection when the app exits
process.on("SIGINT", async () => {
    await mongoose.connection.close();
    console.log("MongoDB connection closed.");
    process.exit(0);
});
