import mongoose, { Schema, Document, Model } from "mongoose";

export interface IOtp extends Document {
    otp: string,
    email: string,
    createdAt: Date,
    expiresAt: Date,
    userId: mongoose.Types.ObjectId,
}

const OTPSchema: Schema<IOtp> = new Schema({
    otp: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    userId: {
        type: Schema.Types.ObjectId,
        required: true,
        ref: "User",
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    expiresAt: {
        type: Date,
        required: false
    },
})

export const OtpModel: Model<IOtp> = mongoose.model<IOtp>('Otp', OTPSchema)