import mongoose, { Schema, Document, Model } from "mongoose";
import { fa } from "zod/v4/locales";

// TypeScript interface for User document
export interface IUser extends Document {
    name: string;
    email: string;
    photo?: string;
    githubId?: string;
    password?: string;
    isGitConnected: boolean;
    createdAt: Date;
}

// User schema
const UserSchema: Schema<IUser> = new Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    photo: {
        type: String,
        required: false
    },
    githubId: {
        type: String,
        required: false,
        unique: true,
        sparse: true
    },
    password: {
        type: String,
        required: false,
    },
    isGitConnected: {
        type: Boolean,
        default: false,
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
});

// User model
export const UserModel: Model<IUser> = mongoose.model<IUser>("User", UserSchema);
