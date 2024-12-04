import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { User } from './schema/user.schema';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { VerifyOTPDto } from './dto/verify-otp.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import * as nodemailer from 'nodemailer';
import * as crypto from 'crypto';
import * as dotenv from 'dotenv';
dotenv.config();

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<User>,
        private jwtService: JwtService,
    ) { }

    async register(dto: RegisterDto) {
        const { email, surname, rsaPIN, password } = dto;

        const existingUser = await this.userModel.findOne({ email });
        if (existingUser) throw new BadRequestException('Email already exists');

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new this.userModel({ email, surname, rsaPIN, password: hashedPassword });
        const otp = crypto.randomInt(100000, 999999);
        await this.sendEmail(email, 'Verify Account', `Your verification code: ${otp}. Code will expire in an hour`);
        user.otp = otp;
        user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
        await user.save();

        return {
            status: 201,
            success: true,
            message: 'Registration successful.'
        };
    }

    async login(dto: LoginDto) {
        const { email, password } = dto;

        const user = await this.userModel.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            throw new BadRequestException('Invalid credentials');
        }

        if (!user.isUserVerified) {
            const otp = crypto.randomInt(100000, 999999);
            await this.sendEmail(email, 'Verify Account', `Your verification code: ${otp}. Code will expire in an hour`);
            user.otp = otp;
            user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
            await user.save();
            throw new BadRequestException('Account not verified. Check your email for new verification code.');
        }

        const token = this.jwtService.sign({ id: user._id });
        return {
            status: 201,
            token,
            success: true,
            message: 'Logged In successful'
        };
    }

    async forgetPassword(dto: ForgetPasswordDto) {
        const { email } = dto;

        const user = await this.userModel.findOne({ email });
        if (!user) throw new BadRequestException('User not found');


        const token = this.jwtService.sign({ id: user._id });
        user.forgetPasswordToken = token;
        user.TokenExpiry = new Date(Date.now() + 10 * 60 * 1000);;
        await user.save();

        await this.sendEmail(email, 'Reset Password', `click link to reset password ${process.env.ALLOWED_DOMAIN}/reset-password/${token}  This link will expire in an hour`);
        return {
            status: 200,
            success: true,
            message: 'Password reset link sent to your email.'
        };
    }

    async verifyOTP(dto: VerifyOTPDto) {
        const { email, otp } = dto;

        const token = await this.validateOTP(email, otp);

        return {
            status: 200,
            token,
            success: true,
            message: 'Account verified successfully.'
        };
    }

    async resetPassword(dto: ResetPasswordDto) {
        const { email, token, newPassword } = dto;

        const user = await this.userModel.findOne({ email });

        await this.validateToken(email, token);

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.forgetPasswordToken = null;
        user.TokenExpiry = null;
        await user.save();

        return {
            status: 200,
            success: true,
            message: 'Password reset successfully.'
        };
    }
    ;
    private async validateOTP(email: string, otp: number) {
        const user = await this.userModel.findOne({ email });

        if (!user) {
            throw new BadRequestException('User not found');
        }

        if (!user.otp || user.otp !== otp) {
            throw new BadRequestException('Invalid OTP');
        }

        if (user.otpExpiry && user.otpExpiry < new Date()) {
            throw new BadRequestException('OTP has expired');
        }

        const token = this.jwtService.sign({ id: user._id });

        user.otp = null;
        user.otpExpiry = null;
        await user.save();

        return { token };

    }

    private async validateToken(email: string, token: string) {
        const user = await this.userModel.findOne({ email });

        if (!user) {
            throw new BadRequestException('User not found');
        }

        if (!user.forgetPasswordToken || user.forgetPasswordToken !== token) {
            throw new BadRequestException('Invalid Token');
        }

    }

    private async sendEmail(to: string, subject: string, text: string) {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        await transporter.sendMail({ from: process.env.EMAIL_USER, to, subject, text });
    }
}
