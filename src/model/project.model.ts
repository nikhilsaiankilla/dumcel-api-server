import mongoose, { Schema, Document, Model } from "mongoose";

// TypeScript interface for Project document
export interface IProject extends Document {
    projectName: string;
    userId: mongoose.Types.ObjectId;
    gitUrl: string;
    subDomain: string;
    createdAt: Date;
    updatedAt: Date;
}

// Project schema
const ProjectSchema: Schema<IProject> = new Schema({
    projectName: {
        type: String,
        required: true,
        trim: true,
        unique: false,
    },
    userId: {
        type: Schema.Types.ObjectId,
        required: true,
        ref: "User",
    },
    gitUrl: {
        type: String,
        required: true,
        trim: true,
    },
    subDomain: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    },
});

// Pre-save hook to update updatedAt
ProjectSchema.pre<IProject>("save", function (next) {
    this.updatedAt = new Date();
    next();
});

// Project model
export const ProjectModel: Model<IProject> = mongoose.model<IProject>("Project", ProjectSchema);
