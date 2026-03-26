package com.vikas.authsystem.service;

import com.vikas.authsystem.config.MailProperties;
import com.vikas.authsystem.exception.ServiceUnavailableException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(prefix = "app.mail", name = "delivery-mode", havingValue = "smtp")
public class SmtpOtpDeliveryService implements OtpDeliveryService {

    private static final Logger log = LoggerFactory.getLogger(SmtpOtpDeliveryService.class);

    private final JavaMailSender mailSender;
    private final MailProperties mailProperties;

    public SmtpOtpDeliveryService(JavaMailSender mailSender, MailProperties mailProperties) {
        this.mailSender = mailSender;
        this.mailProperties = mailProperties;
    }

    @Override
    public void sendVerificationOtp(String email, String otp, long expiresInSeconds) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, false, "UTF-8");
            helper.setFrom(requiredFromAddress());
            helper.setTo(email);
            helper.setSubject(mailProperties.getVerificationSubject());
            helper.setText(buildPlainTextBody(otp, expiresInSeconds), false);
            mailSender.send(mimeMessage);
            log.info("verification_otp_email_sent email={} expiresInSeconds={}", maskEmail(email), expiresInSeconds);
        } catch (MessagingException | MailException ex) {
            log.error("verification_otp_email_failed email={} error={}", maskEmail(email), ex.getMessage());
            throw new ServiceUnavailableException("OTP delivery is temporarily unavailable. Please try again.");
        }
    }

    @Override
    public void sendPasswordResetOtp(String email, String otp, long expiresInSeconds) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, false, "UTF-8");
            helper.setFrom(requiredFromAddress());
            helper.setTo(email);
            helper.setSubject(mailProperties.getPasswordResetSubject());
            helper.setText(buildPasswordResetBody(otp, expiresInSeconds), false);
            mailSender.send(mimeMessage);
            log.info("password_reset_otp_email_sent email={} expiresInSeconds={}", maskEmail(email), expiresInSeconds);
        } catch (MessagingException | MailException ex) {
            log.error("password_reset_otp_email_failed email={} error={}", maskEmail(email), ex.getMessage());
            throw new ServiceUnavailableException("OTP delivery is temporarily unavailable. Please try again.");
        }
    }

    @Override
    public void sendAccountUnlockOtp(String email, String otp, long expiresInSeconds) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, false, "UTF-8");
            helper.setFrom(requiredFromAddress());
            helper.setTo(email);
            helper.setSubject(mailProperties.getAccountUnlockSubject());
            helper.setText(buildAccountUnlockBody(otp, expiresInSeconds), false);
            mailSender.send(mimeMessage);
            log.info("account_unlock_otp_email_sent email={} expiresInSeconds={}", maskEmail(email), expiresInSeconds);
        } catch (MessagingException | MailException ex) {
            log.error("account_unlock_otp_email_failed email={} error={}", maskEmail(email), ex.getMessage());
            throw new ServiceUnavailableException("OTP delivery is temporarily unavailable. Please try again.");
        }
    }

    private String requiredFromAddress() {
        if (mailProperties.getFrom() == null || mailProperties.getFrom().isBlank()) {
            throw new IllegalStateException("app.mail.from must be configured when SMTP delivery is enabled");
        }
        return mailProperties.getFrom().trim();
    }

    private String buildPlainTextBody(String otp, long expiresInSeconds) {
        long expiresInMinutes = Math.max(1, Math.round(expiresInSeconds / 60.0));
        return """
                Hello,

                Use the following one-time password to verify your email address:

                %s

                This code expires in %d minute(s). If you did not create this account, you can ignore this message.

                Thanks,
                AuthSystem Security
                """.formatted(otp, expiresInMinutes);
    }

    private String buildPasswordResetBody(String otp, long expiresInSeconds) {
        long expiresInMinutes = Math.max(1, Math.round(expiresInSeconds / 60.0));
        return """
                Hello,

                Use the following one-time password to reset your account password:

                %s

                This code expires in %d minute(s). If you did not request a password reset, ignore this email and review your account security.

                Thanks,
                AuthSystem Security
                """.formatted(otp, expiresInMinutes);
    }

    private String buildAccountUnlockBody(String otp, long expiresInSeconds) {
        long expiresInMinutes = Math.max(1, Math.round(expiresInSeconds / 60.0));
        return """
                Hello,

                Your account is temporarily protected because of repeated failed sign-in attempts.

                Use the following one-time password to unlock sign-in for your account:

                %s

                This code expires in %d minute(s). If you did not request this unlock, ignore this email and consider changing your password.

                Thanks,
                AuthSystem Security
                """.formatted(otp, expiresInMinutes);
    }

    private String maskEmail(String email) {
        int separatorIndex = email.indexOf('@');
        if (separatorIndex <= 1) {
            return "***" + email.substring(Math.max(separatorIndex, 0));
        }
        return email.charAt(0) + "***" + email.substring(separatorIndex - 1);
    }
}
