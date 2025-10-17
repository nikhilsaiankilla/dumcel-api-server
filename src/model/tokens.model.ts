import mongoose, { Schema, Document, Model } from "mongoose";
import { IUser } from "./user.model";

export interface IToken extends Document {
    user: mongoose.Types.ObjectId | IUser;
    provider: "github";
    accessToken: string;
    createdAt: Date;
}

const TokenSchema: Schema<IToken> = new Schema({
    user: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true,
        index: true,
    },
    provider: {
        type: String,
        enum: ["github"],
        required: true,
    },
    accessToken: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
});

// You might want one token per user+provider
TokenSchema.index({ user: 1, provider: 1 }, { unique: true });

export const TokenModel: Model<IToken> = mongoose.model<IToken>("Token", TokenSchema);
