package com.vikas.authsystem.service;

import com.vikas.authsystem.config.LoginProtectionProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

@Service
public class LoginProtectionService {

    private static final Logger log = LoggerFactory.getLogger(LoginProtectionService.class);
    private static final String LOGIN_KEY_PREFIX = "auth:login:";
    private static final DefaultRedisScript<Long> INCREMENT_WITH_TTL_SCRIPT = new DefaultRedisScript<>(
            """
            local current = redis.call('INCR', KEYS[1])
            if current == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return current
            """,
            Long.class
    );

    private final StringRedisTemplate redisTemplate;
    private final LoginProtectionProperties properties;
    private final AuthMetricsService authMetricsService;
    private final Clock clock;

    public LoginProtectionService(
            StringRedisTemplate redisTemplate,
            LoginProtectionProperties properties,
            AuthMetricsService authMetricsService,
            Clock clock
    ) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
        this.authMetricsService = authMetricsService;
        this.clock = clock;
    }

    public PreAuthenticationDecision evaluateAttempt(String email, String ipAddress) {
        String normalizedEmail = normalize(email);
        String normalizedIp = normalize(ipAddress);
        String accountToken = hashIdentifier(normalizedEmail);
        String ipToken = hashIdentifier(normalizedIp);
        try {
            BlockDecision suspiciousBlock = detectExistingBlock(suspiciousIpBlockKey(ipToken), "login", "ip");
            if (suspiciousBlock.blocked()) {
                return PreAuthenticationDecision.throttled(suspiciousBlock.retryAfterSeconds(), "suspicious_ip");
            }

            BlockDecision burstDecision = evaluateRequestRate(ipBurstKey(ipToken), properties.getIpBurst(), "login", "ip_burst");
            if (burstDecision.blocked()) {
                activateBlock(ipBurstBlockKey(ipToken), properties.getIpBurst().getBlockSeconds());
                return PreAuthenticationDecision.throttled(
                        Math.max(burstDecision.retryAfterSeconds(), properties.getIpBurst().getBlockSeconds()),
                        "ip_burst"
                );
            }

            BlockDecision sustainedDecision = evaluateRequestRate(ipSustainedKey(ipToken), properties.getIpSustained(), "login", "ip_sustained");
            if (sustainedDecision.blocked()) {
                activateBlock(ipSustainedBlockKey(ipToken), properties.getIpSustained().getBlockSeconds());
                return PreAuthenticationDecision.throttled(
                        Math.max(sustainedDecision.retryAfterSeconds(), properties.getIpSustained().getBlockSeconds()),
                        "ip_sustained"
                );
            }

            BlockDecision burstBlock = detectExistingBlock(ipBurstBlockKey(ipToken), "login", "ip_burst");
            if (burstBlock.blocked()) {
                return PreAuthenticationDecision.throttled(burstBlock.retryAfterSeconds(), "ip_burst");
            }

            BlockDecision sustainedBlock = detectExistingBlock(ipSustainedBlockKey(ipToken), "login", "ip_sustained");
            if (sustainedBlock.blocked()) {
                return PreAuthenticationDecision.throttled(sustainedBlock.retryAfterSeconds(), "ip_sustained");
            }

            BlockDecision accountIpBlock = detectExistingBlock(accountIpBlockKey(accountToken, ipToken), "login", "account_ip");
            if (accountIpBlock.blocked()) {
                return PreAuthenticationDecision.throttled(accountIpBlock.retryAfterSeconds(), "account_ip");
            }
            return PreAuthenticationDecision.allowed();
        } catch (RuntimeException ex) {
            authMetricsService.recordRedisDecision("login_protection", "evaluate", "backend_error");
            log.warn("login_protection_evaluation_failed emailHash={} ipHash={} error={}", accountToken, ipToken, ex.getMessage());
            return PreAuthenticationDecision.allowed();
        }
    }

    public FailureDecision recordFailedAttempt(String email, String ipAddress) {
        String normalizedEmail = normalize(email);
        String normalizedIp = normalize(ipAddress);
        String accountToken = hashIdentifier(normalizedEmail);
        String ipToken = hashIdentifier(normalizedIp);
        try {
            boolean accountIpThrottled = evaluateAccountIpFailure(accountToken, ipToken);
            AccountProtectionOutcome protectionOutcome = evaluateAccountProtection(accountToken);
            boolean suspiciousIpThrottled = evaluateSuspiciousIp(accountToken, ipToken);
            return new FailureDecision(
                    accountIpThrottled,
                    protectionOutcome.activated(),
                    suspiciousIpThrottled,
                    Math.max(protectionOutcome.retryAfterSeconds(), retryAfterSeconds(accountIpBlockKey(accountToken, ipToken)))
            );
        } catch (RuntimeException ex) {
            authMetricsService.recordRedisDecision("login_protection", "failure", "backend_error");
            log.warn("login_protection_failure_record_failed emailHash={} ipHash={} error={}", accountToken, ipToken, ex.getMessage());
            return FailureDecision.noop();
        }
    }

    public boolean isAccountProtectionActive(String email) {
        String accountToken = hashIdentifier(normalize(email));
        try {
            return Boolean.TRUE.equals(redisTemplate.hasKey(accountProtectionKey(accountToken)));
        } catch (RuntimeException ex) {
            authMetricsService.recordRedisDecision("login_protection", "account_protection_check", "backend_error");
            log.warn("login_protection_check_failed emailHash={} error={}", accountToken, ex.getMessage());
            return false;
        }
    }

    public boolean isRecoveryEligible(String email, String ipAddress) {
        String accountToken = hashIdentifier(normalize(email));
        String ipToken = hashIdentifier(normalize(ipAddress));
        try {
            return Boolean.TRUE.equals(redisTemplate.hasKey(accountProtectionKey(accountToken)))
                    || Boolean.TRUE.equals(redisTemplate.hasKey(accountIpBlockKey(accountToken, ipToken)));
        } catch (RuntimeException ex) {
            authMetricsService.recordRedisDecision("login_protection", "recovery_eligibility", "backend_error");
            log.warn("login_protection_recovery_eligibility_failed emailHash={} ipHash={} error={}", accountToken, ipToken, ex.getMessage());
            return false;
        }
    }

    public void clearSuccess(String email, String ipAddress) {
        String accountToken = hashIdentifier(normalize(email));
        String ipToken = hashIdentifier(normalize(ipAddress));
        try {
            redisTemplate.delete(List.of(
                    accountIpFailuresKey(accountToken, ipToken),
                    accountIpBlockKey(accountToken, ipToken),
                    accountFailuresKey(accountToken),
                    accountProtectionKey(accountToken)
            ));
            authMetricsService.recordProtectionAction("account", "cleared");
        } catch (RuntimeException ex) {
            authMetricsService.recordRedisDecision("login_protection", "clear", "backend_error");
            log.warn("login_protection_clear_failed emailHash={} ipHash={} error={}", accountToken, ipToken, ex.getMessage());
        }
    }

    public void clearRecoveryState(String email, String ipAddress) {
        clearRecoveryStateByIpHash(email, hashIdentifier(normalize(ipAddress)));
    }

    public void clearRecoveryStateByIpHash(String email, String ipHash) {
        String accountToken = hashIdentifier(normalize(email));
        try {
            redisTemplate.delete(List.of(
                    accountFailuresKey(accountToken),
                    accountProtectionKey(accountToken),
                    accountStrikeKey(accountToken),
                    accountIpFailuresKey(accountToken, ipHash),
                    accountIpBlockKey(accountToken, ipHash),
                    accountIpStrikeKey(accountToken, ipHash)
            ));
            authMetricsService.recordProtectionAction("account_recovery", "cleared");
        } catch (RuntimeException ex) {
            authMetricsService.recordRedisDecision("login_protection", "recovery_clear", "backend_error");
            log.warn("login_protection_recovery_clear_failed emailHash={} ipHash={} error={}", accountToken, ipHash, ex.getMessage());
        }
    }

    public String hashIpAddress(String ipAddress) {
        return hashIdentifier(normalize(ipAddress));
    }

    private BlockDecision evaluateRequestRate(
            String key,
            LoginProtectionProperties.Limit limit,
            String limiter,
            String scope
    ) {
        long currentCount = incrementCounter(key, limit.getWindowSeconds());
        if (currentCount > limit.getMaxAttempts()) {
            authMetricsService.recordRateLimitDecision(limiter, scope, "rejected");
            return new BlockDecision(true, retryAfterSeconds(key));
        }
        authMetricsService.recordRateLimitDecision(limiter, scope, "allowed");
        return BlockDecision.allowed();
    }

    private BlockDecision detectExistingBlock(String key, String limiter, String scope) {
        if (Boolean.TRUE.equals(redisTemplate.hasKey(key))) {
            authMetricsService.recordRateLimitDecision(limiter, scope, "blocked");
            return new BlockDecision(true, retryAfterSeconds(key));
        }
        return BlockDecision.allowed();
    }

    private boolean evaluateAccountIpFailure(String accountToken, String ipToken) {
        LoginProtectionProperties.AccountIpProtection protection = properties.getAccountIp();
        long failures = incrementCounter(accountIpFailuresKey(accountToken, ipToken), protection.getWindowSeconds());
        if (failures > protection.getFailureThreshold()) {
            if (!Boolean.TRUE.equals(redisTemplate.hasKey(accountIpBlockKey(accountToken, ipToken)))) {
                long strikeCount = incrementCounter(
                        accountIpStrikeKey(accountToken, ipToken),
                        protection.getStrikeWindowSeconds()
                );
                long durationSeconds = strikeCount <= 1
                        ? protection.getInitialBlockSeconds()
                        : protection.getRepeatBlockSeconds();
                durationSeconds = Math.min(durationSeconds, protection.getMaxBlockSeconds());
                activateBlock(accountIpBlockKey(accountToken, ipToken), durationSeconds);
                authMetricsService.recordProtectionAction("account_ip", strikeCount <= 1 ? "activated" : "escalated");
            }
            authMetricsService.recordRateLimitDecision("login", "account_ip", "rejected");
            return true;
        }
        authMetricsService.recordRateLimitDecision("login", "account_ip", "allowed");
        return false;
    }

    private AccountProtectionOutcome evaluateAccountProtection(String accountToken) {
        LoginProtectionProperties.AccountProtection protection = properties.getAccountProtection();
        long failures = incrementCounter(accountFailuresKey(accountToken), protection.getWindowSeconds());
        if (failures < protection.getFailureThreshold()) {
            return AccountProtectionOutcome.inactive();
        }
        String protectionKey = accountProtectionKey(accountToken);
        if (Boolean.TRUE.equals(redisTemplate.hasKey(protectionKey))) {
            return new AccountProtectionOutcome(false, retryAfterSeconds(protectionKey));
        }

        long strikeCount = incrementCounter(accountStrikeKey(accountToken), protection.getStrikeWindowSeconds());
        long durationSeconds = strikeCount <= 1
                ? protection.getInitialProtectionSeconds()
                : protection.getRepeatProtectionSeconds();
        durationSeconds = Math.min(durationSeconds, protection.getMaxProtectionSeconds());
        activateBlock(protectionKey, durationSeconds);
        authMetricsService.recordProtectionAction("account", strikeCount <= 1 ? "activated" : "escalated");
        return new AccountProtectionOutcome(true, durationSeconds);
    }

    private boolean evaluateSuspiciousIp(String accountToken, String ipToken) {
        LoginProtectionProperties.SuspiciousIp suspiciousIp = properties.getSuspiciousIp();
        String key = ipAccountSetKey(ipToken);
        redisTemplate.opsForSet().add(key, accountToken);
        redisTemplate.expire(key, Duration.ofSeconds(suspiciousIp.getWindowSeconds()));
        Long distinctAccounts = redisTemplate.opsForSet().size(key);
        if (distinctAccounts != null && distinctAccounts > suspiciousIp.getDistinctAccountsThreshold()) {
            if (!Boolean.TRUE.equals(redisTemplate.hasKey(suspiciousIpBlockKey(ipToken)))) {
                activateBlock(suspiciousIpBlockKey(ipToken), suspiciousIp.getBlockSeconds());
                authMetricsService.recordSuspiciousIpAction("blocked");
            }
            authMetricsService.recordRateLimitDecision("login", "suspicious_ip", "rejected");
            return true;
        }
        return false;
    }

    private long incrementCounter(String key, long ttlSeconds) {
        Long count = redisTemplate.execute(INCREMENT_WITH_TTL_SCRIPT, List.of(key), String.valueOf(ttlSeconds));
        if (count == null) {
            throw new IllegalStateException("Failed to update login protection counter");
        }
        authMetricsService.recordRedisDecision("login_protection", "counter", "success");
        return count;
    }

    private void activateBlock(String key, long ttlSeconds) {
        redisTemplate.opsForValue().set(key, String.valueOf(Instant.now(clock).getEpochSecond()), Duration.ofSeconds(ttlSeconds));
        authMetricsService.recordRedisDecision("login_protection", "block", "success");
    }

    private long retryAfterSeconds(String key) {
        Long ttl = redisTemplate.getExpire(key);
        return ttl == null || ttl < 0 ? 0 : ttl;
    }

    private String ipBurstKey(String ipToken) {
        return LOGIN_KEY_PREFIX + "ip:burst:" + ipToken;
    }

    private String ipBurstBlockKey(String ipToken) {
        return LOGIN_KEY_PREFIX + "ip:burst:block:" + ipToken;
    }

    private String ipSustainedKey(String ipToken) {
        return LOGIN_KEY_PREFIX + "ip:sustained:" + ipToken;
    }

    private String ipSustainedBlockKey(String ipToken) {
        return LOGIN_KEY_PREFIX + "ip:sustained:block:" + ipToken;
    }

    private String accountIpFailuresKey(String accountToken, String ipToken) {
        return LOGIN_KEY_PREFIX + "account-ip:failures:" + accountToken + ":" + ipToken;
    }

    private String accountIpBlockKey(String accountToken, String ipToken) {
        return LOGIN_KEY_PREFIX + "account-ip:block:" + accountToken + ":" + ipToken;
    }

    private String accountIpStrikeKey(String accountToken, String ipToken) {
        return LOGIN_KEY_PREFIX + "account-ip:strikes:" + accountToken + ":" + ipToken;
    }

    private String accountFailuresKey(String accountToken) {
        return LOGIN_KEY_PREFIX + "account:failures:" + accountToken;
    }

    private String accountProtectionKey(String accountToken) {
        return LOGIN_KEY_PREFIX + "account:protection:" + accountToken;
    }

    private String accountStrikeKey(String accountToken) {
        return LOGIN_KEY_PREFIX + "account:strikes:" + accountToken;
    }

    private String ipAccountSetKey(String ipToken) {
        return LOGIN_KEY_PREFIX + "ip:accounts:" + ipToken;
    }

    private String suspiciousIpBlockKey(String ipToken) {
        return LOGIN_KEY_PREFIX + "ip:suspicious:block:" + ipToken;
    }

    private String hashIdentifier(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 hashing algorithm is not available", ex);
        }
    }

    private String normalize(String value) {
        return value == null ? "unknown" : value.trim().toLowerCase();
    }

    public record PreAuthenticationDecision(boolean throttled, long retryAfterSeconds, String reason) {

        private static PreAuthenticationDecision allowed() {
            return new PreAuthenticationDecision(false, 0, "allowed");
        }

        private static PreAuthenticationDecision throttled(long retryAfterSeconds, String reason) {
            return new PreAuthenticationDecision(true, Math.max(0, retryAfterSeconds), reason);
        }
    }

    public record FailureDecision(
            boolean accountIpThrottled,
            boolean accountProtectionActivated,
            boolean suspiciousIpThrottled,
            long retryAfterSeconds
    ) {

        private static FailureDecision noop() {
            return new FailureDecision(false, false, false, 0);
        }
    }

    private record BlockDecision(boolean blocked, long retryAfterSeconds) {

        private static BlockDecision allowed() {
            return new BlockDecision(false, 0);
        }
    }

    private record AccountProtectionOutcome(boolean activated, long retryAfterSeconds) {

        private static AccountProtectionOutcome inactive() {
            return new AccountProtectionOutcome(false, 0);
        }
    }
}
