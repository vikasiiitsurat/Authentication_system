package com.vikas.authsystem.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.rate-limit")
public class RateLimitProperties {

    private final Limit login = new Limit();
    private final Limit otpGeneration = new Limit();
    private final Limit otpVerification = new Limit();
    private final Limit passwordResetRequest = new Limit();
    private final Limit passwordResetConfirmation = new Limit();

    public Limit getLogin() {
        return login;
    }

    public Limit getOtpGeneration() {
        return otpGeneration;
    }

    public Limit getOtpVerification() {
        return otpVerification;
    }

    public Limit getPasswordResetRequest() {
        return passwordResetRequest;
    }

    public Limit getPasswordResetConfirmation() {
        return passwordResetConfirmation;
    }

    public static class Limit {

        private int maxAttempts;
        private long windowSeconds;

        public int getMaxAttempts() {
            return maxAttempts;
        }

        public void setMaxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
        }

        public long getWindowSeconds() {
            return windowSeconds;
        }

        public void setWindowSeconds(long windowSeconds) {
            this.windowSeconds = windowSeconds;
        }
    }
}
