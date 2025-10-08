import mongoose, { Schema, Document, Model } from "mongoose";

export interface IOtp extends Document {
    otp: string,
    email: string,
    userId: string,
    createdAt: Date,
    expiresAt: Date,
}

const OTPSchema: Schema<IOtp> = new Schema({
    otp: { type: String, required: true },
    email: { type: String, required: true },
    userId: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: false },
})

export const OtpModel: Model<IOtp> = mongoose.model<IOtp>('Otp', OTPSchema)