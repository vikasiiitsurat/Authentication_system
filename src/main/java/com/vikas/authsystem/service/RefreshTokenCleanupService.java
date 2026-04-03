package com.vikas.authsystem.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class RefreshTokenCleanupService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenCleanupService.class);

    private final RefreshTokenService refreshTokenService;

    public RefreshTokenCleanupService(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
    }

    @Scheduled(cron = "${app.cleanup.refresh-token-cron}")
    public void deleteExpiredRefreshTokens() {
        int deletedCount = refreshTokenService.deleteExpiredRefreshTokens();
        if (deletedCount > 0) {
            log.info("refresh_token_cleanup_deleted count={}", deletedCount);
        }
    }
}
