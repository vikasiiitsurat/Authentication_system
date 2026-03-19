package com.vikas.authsystem.service;

public interface OtpDeliveryService {

    void sendVerificationOtp(String email, String otp, long expiresInSeconds);
}
