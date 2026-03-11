package com.vikas.authsystem.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.rate-limit.login")
public class RateLimitProperties {

    private int maxAttemptsPerMinute;
    private long windowSeconds;

    public int getMaxAttemptsPerMinute() {
        return maxAttemptsPerMinute;
    }

    public void setMaxAttemptsPerMinute(int maxAttemptsPerMinute) {
        this.maxAttemptsPerMinute = maxAttemptsPerMinute;
    }

    public long getWindowSeconds() {
        return windowSeconds;
    }

    public void setWindowSeconds(long windowSeconds) {
        this.windowSeconds = windowSeconds;
    }
}
