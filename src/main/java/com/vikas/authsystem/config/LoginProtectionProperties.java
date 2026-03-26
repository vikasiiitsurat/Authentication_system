package com.vikas.authsystem.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.login-protection")
public class LoginProtectionProperties {

    private final Limit ipBurst = new Limit();
    private final Limit ipSustained = new Limit();
    private final AccountIpProtection accountIp = new AccountIpProtection();
    private final AccountProtection accountProtection = new AccountProtection();
    private final SuspiciousIp suspiciousIp = new SuspiciousIp();

    public Limit getIpBurst() {
        return ipBurst;
    }

    public Limit getIpSustained() {
        return ipSustained;
    }

    public AccountIpProtection getAccountIp() {
        return accountIp;
    }

    public AccountProtection getAccountProtection() {
        return accountProtection;
    }

    public SuspiciousIp getSuspiciousIp() {
        return suspiciousIp;
    }

    public static class Limit {

        private int maxAttempts;
        private long windowSeconds;
        private long blockSeconds;

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

        public long getBlockSeconds() {
            return blockSeconds;
        }

        public void setBlockSeconds(long blockSeconds) {
            this.blockSeconds = blockSeconds;
        }
    }

    public static class AccountIpProtection {

        private int failureThreshold;
        private long windowSeconds;
        private long initialBlockSeconds;
        private long repeatBlockSeconds;
        private long maxBlockSeconds;
        private long strikeWindowSeconds;

        public int getFailureThreshold() {
            return failureThreshold;
        }

        public void setFailureThreshold(int failureThreshold) {
            this.failureThreshold = failureThreshold;
        }

        public long getWindowSeconds() {
            return windowSeconds;
        }

        public void setWindowSeconds(long windowSeconds) {
            this.windowSeconds = windowSeconds;
        }

        public long getInitialBlockSeconds() {
            return initialBlockSeconds;
        }

        public void setInitialBlockSeconds(long initialBlockSeconds) {
            this.initialBlockSeconds = initialBlockSeconds;
        }

        public long getRepeatBlockSeconds() {
            return repeatBlockSeconds;
        }

        public void setRepeatBlockSeconds(long repeatBlockSeconds) {
            this.repeatBlockSeconds = repeatBlockSeconds;
        }

        public long getMaxBlockSeconds() {
            return maxBlockSeconds;
        }

        public void setMaxBlockSeconds(long maxBlockSeconds) {
            this.maxBlockSeconds = maxBlockSeconds;
        }

        public long getStrikeWindowSeconds() {
            return strikeWindowSeconds;
        }

        public void setStrikeWindowSeconds(long strikeWindowSeconds) {
            this.strikeWindowSeconds = strikeWindowSeconds;
        }
    }

    public static class AccountProtection {

        private int failureThreshold;
        private long windowSeconds;
        private long initialProtectionSeconds;
        private long repeatProtectionSeconds;
        private long maxProtectionSeconds;
        private long strikeWindowSeconds;

        public int getFailureThreshold() {
            return failureThreshold;
        }

        public void setFailureThreshold(int failureThreshold) {
            this.failureThreshold = failureThreshold;
        }

        public long getWindowSeconds() {
            return windowSeconds;
        }

        public void setWindowSeconds(long windowSeconds) {
            this.windowSeconds = windowSeconds;
        }

        public long getInitialProtectionSeconds() {
            return initialProtectionSeconds;
        }

        public void setInitialProtectionSeconds(long initialProtectionSeconds) {
            this.initialProtectionSeconds = initialProtectionSeconds;
        }

        public long getRepeatProtectionSeconds() {
            return repeatProtectionSeconds;
        }

        public void setRepeatProtectionSeconds(long repeatProtectionSeconds) {
            this.repeatProtectionSeconds = repeatProtectionSeconds;
        }

        public long getMaxProtectionSeconds() {
            return maxProtectionSeconds;
        }

        public void setMaxProtectionSeconds(long maxProtectionSeconds) {
            this.maxProtectionSeconds = maxProtectionSeconds;
        }

        public long getStrikeWindowSeconds() {
            return strikeWindowSeconds;
        }

        public void setStrikeWindowSeconds(long strikeWindowSeconds) {
            this.strikeWindowSeconds = strikeWindowSeconds;
        }
    }

    public static class SuspiciousIp {

        private int distinctAccountsThreshold;
        private long windowSeconds;
        private long blockSeconds;

        public int getDistinctAccountsThreshold() {
            return distinctAccountsThreshold;
        }

        public void setDistinctAccountsThreshold(int distinctAccountsThreshold) {
            this.distinctAccountsThreshold = distinctAccountsThreshold;
        }

        public long getWindowSeconds() {
            return windowSeconds;
        }

        public void setWindowSeconds(long windowSeconds) {
            this.windowSeconds = windowSeconds;
        }

        public long getBlockSeconds() {
            return blockSeconds;
        }

        public void setBlockSeconds(long blockSeconds) {
            this.blockSeconds = blockSeconds;
        }
    }
}
