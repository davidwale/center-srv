import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class User extends Document {
    @Prop({ required: true, unique: true })
    email: string;

    @Prop({ required: true })
    surname: string;

    @Prop({ required: true })
    rsaPIN: number;

    @Prop({ required: true })
    password: string;

    @Prop({ default: false })
    isUserVerified: boolean;

    @Prop({ type: Number, default: null })
    otp: number;

    @Prop({ default: null })
    forgetPasswordToken: string;

    @Prop({ type: Date, default: null })
    otpExpiry: Date;

    @Prop({ type: Date, default: null })
    TokenExpiry: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
