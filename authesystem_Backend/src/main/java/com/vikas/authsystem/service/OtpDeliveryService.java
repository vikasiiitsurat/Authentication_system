package com.vikas.authsystem.service;

public interface OtpDeliveryService {

    void sendVerificationOtp(String email, String otp, long expiresInSeconds);

    void sendPasswordResetOtp(String email, String otp, long expiresInSeconds);

    void sendAccountUnlockOtp(String email, String otp, long expiresInSeconds);

    void sendLoginTwoFactorOtp(String email, String otp, long expiresInSeconds);
}
