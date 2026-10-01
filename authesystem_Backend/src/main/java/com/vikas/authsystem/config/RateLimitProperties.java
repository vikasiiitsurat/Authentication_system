package com.vikas.authsystem.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.rate-limit")
public class RateLimitProperties {

    private final ScopedLimit otpGeneration = new ScopedLimit();
    private final ScopedLimit otpVerification = new ScopedLimit();
    private final ScopedLimit passwordResetRequest = new ScopedLimit();
    private final ScopedLimit passwordResetConfirmation = new ScopedLimit();
    private final ScopedLimit accountUnlockRequest = new ScopedLimit();
    private final ScopedLimit accountUnlockConfirmation = new ScopedLimit();
    private final ScopedLimit loginTwoFactorRequest = new ScopedLimit();
    private final ScopedLimit loginTwoFactorConfirmation = new ScopedLimit();

    public ScopedLimit getOtpGeneration() {
        return otpGeneration;
    }

    public ScopedLimit getOtpVerification() {
        return otpVerification;
    }

    public ScopedLimit getPasswordResetRequest() {
        return passwordResetRequest;
    }

    public ScopedLimit getPasswordResetConfirmation() {
        return passwordResetConfirmation;
    }

    public ScopedLimit getAccountUnlockRequest() {
        return accountUnlockRequest;
    }

    public ScopedLimit getAccountUnlockConfirmation() {
        return accountUnlockConfirmation;
    }

    public ScopedLimit getLoginTwoFactorRequest() {
        return loginTwoFactorRequest;
    }

    public ScopedLimit getLoginTwoFactorConfirmation() {
        return loginTwoFactorConfirmation;
    }

    public static class ScopedLimit {

        private final Limit perAccount = new Limit();
        private final Limit perIp = new Limit();
        private final Limit perAccountIp = new Limit();

        public Limit getPerAccount() {
            return perAccount;
        }

        public Limit getPerIp() {
            return perIp;
        }

        public Limit getPerAccountIp() {
            return perAccountIp;
        }
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
