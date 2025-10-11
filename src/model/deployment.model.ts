import mongoose, { Schema, Document, Model } from "mongoose";

// Enum for deployment states
export enum DeploymentState {
    QUEUED = "queued",
    NOT_STARTED = "not started",
    IN_PROGRESS = "in progress",
    READY = "ready",
    FAILED = "failed",
}

// TypeScript interface for Deployment document
export interface IDeployment extends Document {
    projectId: mongoose.Types.ObjectId;
    state: DeploymentState;
    userId: mongoose.Types.ObjectId;
    createdAt: Date;
    updatedAt: Date;
}

// Deployment schema
const DeploymentSchema: Schema<IDeployment> = new Schema({
    projectId: {
        type: Schema.Types.ObjectId,
        ref: "Project",
        required: true,
    },
    state: {
        type: String,
        enum: Object.values(DeploymentState),
        default: DeploymentState.NOT_STARTED,
        required: true,
    },
    userId: {
        type: Schema.Types.ObjectId,
        required: true,
        ref: "User",
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
DeploymentSchema.pre<IDeployment>("save", function (next) {
    this.updatedAt = new Date();
    next();
});

// Deployment model
export const DeploymentModel: Model<IDeployment> = mongoose.model<IDeployment>(
    "Deployment",
    DeploymentSchema
);
