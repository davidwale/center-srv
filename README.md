# NestJS Authentication API

## Overview

This project is a NestJS application that implements essential authentication features, including:

- **User Registration**: Allows users to create an account with email, surname, password, and other optional details.\
- **Login**: Enables users to log in using their registered email and password.\
- **Email Verification**: Sends a unique one-time password (OTP) to the user's email for verification during registration.\
- **Password Reset**: Provides functionality to reset the password using a secure 6-digit OTP.

## Features

### 1. User Registration

- Users can register by providing the following details:\
  - `email`: Required, must be unique.\
  - `surname`: Required.\
  - `password`: Required, hashed for security.\
  -  `rsaPIN`.\
- Validation ensures all required fields are provided, and existing emails cannot be reused.

### 2. Login

- Authenticates users with their `email` and `password`.\
- Issues a JWT token for secure session handling.

### 3. Email Verification

- Upon registration, a 6-digit OTP is sent to the user's email.\
- The OTP is validated to verify the email address, ensuring the user's identity.

### 4. Password Reset

- Users can initiate a password reset by providing their registered email.\
- A link with a token is sent to their email for verification.\
- After validation, users can set a new password.

## Technologies Used

- **NestJS**: Framework for building efficient, reliable, and scalable server-side applications.\
- **MongoDB**: NoSQL database for managing user data.\
- **Mongoose**: ODM for MongoDB.\
- **bcrypt**: For hashing passwords.\
- **jwt**: For authentication and token generation.\
- **crypto**: For generating secure OTPs.\
- **nodemailer**: For sending emails.\
- **dotenv**: For environment variable management.

## Installation and Setup

### Prerequisites

- Node.js (v16 or later)\
- MongoDB instance\
- A valid email account for testing (Gmail, Yahoo, etc.)

### Steps

1\. **Clone the Repository**:\
   ```bash\
   git clone <repository_url>\
   cd <repository_folder>\
   ```

2\. **Install Dependencies**:\
   ```bash\
   npm install\
   ```

3\. **Set Up Environment Variables**: Create a `.env` file in the root directory and populate it with the following:\
   ```\
   PORT=3000\
   MONGO_URI=mongodb://localhost:27017/nest-auth-db\
   JWT_SECRET=your_jwt_secret\
   SMTP_HOST=smtp.your-email-provider.com\
   SMTP_PORT=587\
   SMTP_USER=your-email@example.com\
   SMTP_PASS=your-email-password\
   ALLOWED_DOMAIN=http://localhost:5173\
   ```

4\. **Run the Application**:\
   ```bash\
   npm run start:dev\
   ```

   The server will start at `http://localhost:3000`.

## Endpoints

### 1. Register\
- **Endpoint**: `POST /auth/register`\
- **Request Body**:\
  ```json\
  {\
    "email": "user@example.com",\
    "surname": "Doe",\
    "password": "securePassword123"\
  }\
  ```\
- **Response**:\
  ```json\
  {\
    "status": 201\
    "success": true\
    "message": "Registration successful"\
  }\
  ```

### 2. Login\
- **Endpoint**: `POST /auth/login`\
- **Request Body**:\
  ```json\
  {\
    "email": "user@example.com",\
    "password": "securePassword123"\
  }\
  ```\
- **Response**:\
  ```json\
  {\
    "status": 200\
    "success": true\
    "token": "jwt_token"\
    "message": "Logged In successful"\
  }\
  ```

### 3. Verify Email\
- **Endpoint**: `POST /auth/verify-otp`\
- **Request Body**:\
  ```json\
  {\
    "email": "user@example.com",\
    "otp": 123456\
  }\
  ```\
- **Response**:\
  ```json\
  {\
    "status": 200\
    "success": true\
    "message": "Email verified successfully"\
  }\
  ```

### 4. Forget Password\
- **Endpoint**: `POST /auth/forget-password`\
- **Request Body**:\
  ```json\
  {\
    "email": "user@example.com"\
  }\
  ```\
- **Response**:\
  ```json\
  {\
    "status": 200\
    "success": true\
    "message": "OTP sent to your email"\
  }\
  ```

### 5. Reset Password\
- **Endpoint**: `POST /auth/reset-password`\
- **Request Body**:\
  ```json\
  {\
    "email": "user@example.com",\
    "otp": 123456,\
    "newPassword": "newSecurePassword123"\
  }\
  ```\
- **Response**:\
  ```json\
  {\
    "status": 200\
    "success": true\
    "message": "Password reset successful"\
  }\
  ```

## Testing

- Use a tool like **Postman** or **cURL** to test the endpoints.\
- Ensure your database (`MONGO_URI`) and email (`SMTP_*`) configurations are correct.

## Author

- **Your Name**: David Oyewale\
- **Role**: Full Stack Developer\

## License

This project is licensed under the MIT License.