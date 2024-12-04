import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class RegisterDto {
    @IsEmail({}, { message: 'Email is invalid' })
    email: string;

    @IsNotEmpty({ message: 'Surname is required' })
    surname: string;

    @IsNotEmpty({ message: 'RSA PIN is required' })
    rsaPIN: string;

    @IsNotEmpty({ message: 'Password is required' })
    @MinLength(6, { message: 'Password must be at least 6 characters long' })
    password: string;
}
