package com.vikas.authsystem.service;

import com.vikas.authsystem.config.MailProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(prefix = "app.mail", name = "delivery-mode", havingValue = "log", matchIfMissing = true)
public class LoggingOtpDeliveryService implements OtpDeliveryService {

    private static final Logger log = LoggerFactory.getLogger(LoggingOtpDeliveryService.class);
    private final MailProperties mailProperties;

    public LoggingOtpDeliveryService(MailProperties mailProperties) {
        this.mailProperties = mailProperties;
    }

    @Override
    public void sendVerificationOtp(String email, String otp, long expiresInSeconds) {
        String otpToken = mailProperties.isLogOtp() ? otp : "<redacted>";
        log.info(
                "verification_otp_dispatched email={} otp={} expiresInSeconds={}",
                maskEmail(email),
                otpToken,
                expiresInSeconds
        );
    }

    @Override
    public void sendPasswordResetOtp(String email, String otp, long expiresInSeconds) {
        String otpToken = mailProperties.isLogOtp() ? otp : "<redacted>";
        log.info(
                "password_reset_otp_dispatched email={} otp={} expiresInSeconds={}",
                maskEmail(email),
                otpToken,
                expiresInSeconds
        );
    }

    private String maskEmail(String email) {
        int separatorIndex = email.indexOf('@');
        if (separatorIndex <= 1) {
            return "***" + email.substring(Math.max(separatorIndex, 0));
        }
        return email.charAt(0) + "***" + email.substring(separatorIndex - 1);
    }
}
