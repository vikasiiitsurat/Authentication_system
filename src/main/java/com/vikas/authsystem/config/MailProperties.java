package com.vikas.authsystem.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.mail")
public class MailProperties {

    private String from;
    private String verificationSubject = "Verify your email address";
    private String passwordResetSubject = "Reset your password";
    private String accountUnlockSubject = "Unlock your account";
    private String loginTwoFactorSubject = "Your login verification code";
    private String deliveryMode = "log";
    private boolean logOtp = true;

    public String getFrom() {
        return from;
    }

    public void setFrom(String from) {
        this.from = from;
    }

    public String getVerificationSubject() {
        return verificationSubject;
    }

    public void setVerificationSubject(String verificationSubject) {
        this.verificationSubject = verificationSubject;
    }

    public String getPasswordResetSubject() {
        return passwordResetSubject;
    }

    public void setPasswordResetSubject(String passwordResetSubject) {
        this.passwordResetSubject = passwordResetSubject;
    }

    public String getAccountUnlockSubject() {
        return accountUnlockSubject;
    }

    public void setAccountUnlockSubject(String accountUnlockSubject) {
        this.accountUnlockSubject = accountUnlockSubject;
    }

    public String getLoginTwoFactorSubject() {
        return loginTwoFactorSubject;
    }

    public void setLoginTwoFactorSubject(String loginTwoFactorSubject) {
        this.loginTwoFactorSubject = loginTwoFactorSubject;
    }

    public String getDeliveryMode() {
        return deliveryMode;
    }

    public void setDeliveryMode(String deliveryMode) {
        this.deliveryMode = deliveryMode;
    }

    public boolean isLogOtp() {
        return logOtp;
    }

    public void setLogOtp(boolean logOtp) {
        this.logOtp = logOtp;
    }
}
