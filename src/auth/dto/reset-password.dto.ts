import { IsNotEmpty, IsEmail } from 'class-validator';

export class ResetPasswordDto {
    @IsEmail({}, { message: 'Email is invalid' })
    email: string;

    @IsNotEmpty({ message: 'Password is required' })
    newPassword: string;

    @IsNotEmpty({ message: 'Verification Token is required' })
    token: string;
}

