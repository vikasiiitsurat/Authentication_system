package com.vikas.authsystem.service;

import com.vikas.authsystem.config.OtpProperties;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.exception.BadRequestException;
import com.vikas.authsystem.exception.TooManyRequestsException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@Service
public class LoginTwoFactorChallengeService {

    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final Duration RESEND_COOLDOWN = Duration.ofSeconds(60);
    private static final Duration GENERATION_LIMIT_WINDOW = Duration.ofHours(1);
    private static final Duration RESEND_LIMIT_WINDOW = Duration.ofMinutes(15);
    private static final int MAX_ATTEMPTS = 5;
    private static final int MAX_GENERATIONS_PER_WINDOW = 5;
    private static final int MAX_RESENDS_PER_WINDOW = 3;
    private static final String USER_KEY_PREFIX = "auth:login-2fa:user:";
    private static final String TOKEN_KEY_PREFIX = "auth:login-2fa:token:";
    private static final String GENERATION_COUNTER_KEY_PREFIX = "auth:login-2fa:generation-count:";
    private static final String RESEND_COUNTER_KEY_PREFIX = "auth:login-2fa:resend-count:";

    private final StringRedisTemplate redisTemplate;
    private final Clock clock;
    private final SecretKeySpec otpSecretKey;
    private final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    public LoginTwoFactorChallengeService(StringRedisTemplate redisTemplate, OtpProperties otpProperties) {
        this(redisTemplate, otpProperties, Clock.systemUTC());
    }

    LoginTwoFactorChallengeService(StringRedisTemplate redisTemplate, OtpProperties otpProperties, Clock clock) {
        this.redisTemplate = redisTemplate;
        this.clock = clock;
        this.otpSecretKey = buildOtpSecretKey(otpProperties);
    }

    public ChallengeIssueResult issueChallenge(User user, String deviceId, String clientIpHash) {
        invalidateChallenge(user.getId());
        enforceGenerationBudget(user.getId());
        return createChallenge(
                user.getId(),
                user.getEmail(),
                normalizeDeviceId(deviceId),
                normalizeClientIpHash(clientIpHash),
                Instant.now(clock)
        );
    }

    public ChallengeIssueResult resendChallenge(String challengeToken, String clientIpHash) {
        ChallengeContext context = getRequiredChallengeContext(challengeToken);
        ensureClientContext(context.clientIpHash(), clientIpHash);

        long resendAvailableInSeconds = Math.max(
                0,
                context.resendAvailableAtEpochSecond() - Instant.now(clock).getEpochSecond()
        );
        if (resendAvailableInSeconds > 0) {
            throw new TooManyRequestsException(
                    "Login verification code can be resent in " + resendAvailableInSeconds + " seconds.",
                    resendAvailableInSeconds
            );
        }

        enforceResendBudget(context.userId());
        String userKey = userKey(context.userId());
        redisTemplate.opsForHash().put(
                userKey,
                "resendAvailableAtEpochSecond",
                String.valueOf(Instant.now(clock).plus(RESEND_COOLDOWN).getEpochSecond())
        );

        return new ChallengeIssueResult(
                context.challengeToken(),
                generateOtp(context.userId(), context.createdAtEpochSecond(), context.challengeToken()),
                remainingSeconds(userKey),
                RESEND_COOLDOWN.toSeconds(),
                context.userId(),
                context.email(),
                context.deviceId()
        );
    }

    public ChallengeVerificationResult verifyChallenge(String challengeToken, String providedOtp, String clientIpHash) {
        ChallengeContext context = getRequiredChallengeContext(challengeToken);
        ensureClientContext(context.clientIpHash(), clientIpHash);

        String userKey = userKey(context.userId());
        HashOperations<String, Object, Object> hashOperations = redisTemplate.opsForHash();
        Map<Object, Object> values = hashOperations.entries(userKey);
        if (values.isEmpty()) {
            deleteTokenLookup(context.challengeToken());
            throw new BadRequestException("Login verification challenge has expired or is invalid");
        }

        int attempts = parseInteger(values.get("attemptCount")) + 1;
        hashOperations.put(userKey, "attemptCount", String.valueOf(attempts));
        if (attempts > MAX_ATTEMPTS) {
            invalidateChallenge(context.userId());
            throw new BadRequestException("Login verification attempts exceeded. Start login again.");
        }

        String expectedHash = String.valueOf(values.get("otpHash"));
        if (!MessageDigest.isEqual(hashOtp(providedOtp).getBytes(StandardCharsets.UTF_8), expectedHash.getBytes(StandardCharsets.UTF_8))) {
            throw new BadRequestException("Invalid login verification code. " + (MAX_ATTEMPTS - attempts) + " attempts remaining.");
        }

        long remainingSeconds = remainingSeconds(userKey);
        invalidateChallenge(context.userId());
        return new ChallengeVerificationResult(
                context.userId(),
                context.email(),
                context.deviceId(),
                context.createdAtEpochSecond(),
                Math.max(0, remainingSeconds)
        );
    }

    public ChallengeContext getRequiredChallengeContext(String challengeToken) {
        String token = normalizeChallengeToken(challengeToken);
        String userIdValue = redisTemplate.opsForValue().get(tokenKey(token));
        if (userIdValue == null || userIdValue.isBlank()) {
            throw new BadRequestException("Login verification challenge has expired or is invalid");
        }

        UUID userId = parseUuid(userIdValue);
        String userKey = userKey(userId);
        Map<Object, Object> values = redisTemplate.opsForHash().entries(userKey);
        if (values.isEmpty()) {
            deleteTokenLookup(token);
            throw new BadRequestException("Login verification challenge has expired or is invalid");
        }

        String storedToken = String.valueOf(values.get("challengeToken"));
        if (!safeEquals(storedToken, token)) {
            deleteTokenLookup(token);
            throw new BadRequestException("Login verification challenge has expired or is invalid");
        }

        return new ChallengeContext(
                userId,
                String.valueOf(values.get("email")),
                String.valueOf(values.get("deviceId")),
                String.valueOf(values.get("clientIpHash")),
                storedToken,
                parseLong(values.get("createdAtEpochSecond")),
                parseLong(values.get("resendAvailableAtEpochSecond"))
        );
    }

    public void invalidateChallenge(UUID userId) {
        String userKey = userKey(userId);
        Map<Object, Object> values = redisTemplate.opsForHash().entries(userKey);
        if (!values.isEmpty()) {
            Object challengeToken = values.get("challengeToken");
            if (challengeToken != null) {
                deleteTokenLookup(String.valueOf(challengeToken));
            }
        }
        redisTemplate.delete(userKey);
    }

    private ChallengeIssueResult createChallenge(
            UUID userId,
            String email,
            String deviceId,
            String clientIpHash,
            Instant now
    ) {
        String challengeToken = generateChallengeToken();
        String otp = generateOtp(userId, now.getEpochSecond(), challengeToken);
        String userKey = userKey(userId);
        redisTemplate.opsForHash().putAll(userKey, Map.of(
                "challengeToken", challengeToken,
                "email", email,
                "deviceId", deviceId,
                "clientIpHash", clientIpHash,
                "otpHash", hashOtp(otp),
                "attemptCount", "0",
                "createdAtEpochSecond", String.valueOf(now.getEpochSecond()),
                "resendAvailableAtEpochSecond", String.valueOf(now.plus(RESEND_COOLDOWN).getEpochSecond())
        ));
        redisTemplate.expire(userKey, CHALLENGE_TTL);
        redisTemplate.opsForValue().set(tokenKey(challengeToken), userId.toString(), CHALLENGE_TTL);

        return new ChallengeIssueResult(
                challengeToken,
                otp,
                CHALLENGE_TTL.toSeconds(),
                RESEND_COOLDOWN.toSeconds(),
                userId,
                email,
                deviceId
        );
    }

    private void ensureClientContext(String expectedClientIpHash, String providedClientIpHash) {
        if (!safeEquals(expectedClientIpHash, normalizeClientIpHash(providedClientIpHash))) {
            throw new BadRequestException("Login verification challenge has expired or is invalid");
        }
    }

    private void enforceGenerationBudget(UUID userId) {
        String key = GENERATION_COUNTER_KEY_PREFIX + userId;
        long count = incrementCounter(key, GENERATION_LIMIT_WINDOW);
        if (count > MAX_GENERATIONS_PER_WINDOW) {
            throw new TooManyRequestsException(
                    "Too many login verification requests. Please try again later.",
                    remainingSeconds(key)
            );
        }
    }

    private void enforceResendBudget(UUID userId) {
        String key = RESEND_COUNTER_KEY_PREFIX + userId;
        long count = incrementCounter(key, RESEND_LIMIT_WINDOW);
        if (count > MAX_RESENDS_PER_WINDOW) {
            throw new TooManyRequestsException(
                    "Too many login verification resends. Please try again later.",
                    remainingSeconds(key)
            );
        }
    }

    private long incrementCounter(String key, Duration ttl) {
        Long count = redisTemplate.opsForValue().increment(key);
        if (count == null) {
            throw new IllegalStateException("Failed to evaluate login 2FA limits");
        }
        if (count == 1L) {
            redisTemplate.expire(key, ttl);
        }
        return count;
    }

    private long remainingSeconds(String key) {
        Long ttl = redisTemplate.getExpire(key);
        return ttl == null || ttl < 0 ? 0 : ttl;
    }

    private String userKey(UUID userId) {
        return USER_KEY_PREFIX + userId;
    }

    private String tokenKey(String challengeToken) {
        return TOKEN_KEY_PREFIX + normalizeChallengeToken(challengeToken);
    }

    private void deleteTokenLookup(String challengeToken) {
        redisTemplate.delete(tokenKey(challengeToken));
    }

    private String normalizeChallengeToken(String challengeToken) {
        return challengeToken == null ? "" : challengeToken.trim();
    }

    private String normalizeDeviceId(String deviceId) {
        return (deviceId == null || deviceId.isBlank()) ? "unknown-device" : deviceId.trim();
    }

    private String normalizeClientIpHash(String clientIpHash) {
        return (clientIpHash == null || clientIpHash.isBlank()) ? "unknown-ip" : clientIpHash.trim();
    }

    private String generateChallengeToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String generateOtp(UUID userId, long createdAtEpochSecond, String challengeToken) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(otpSecretKey);
            byte[] hash = mac.doFinal((userId + ":" + createdAtEpochSecond + ":" + challengeToken + ":login-2fa")
                    .getBytes(StandardCharsets.UTF_8));
            int code = (ByteBuffer.wrap(hash, 0, Integer.BYTES).getInt() & Integer.MAX_VALUE) % 1_000_000;
            return String.format("%06d", code);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate login verification OTP", ex);
        }
    }

    private SecretKeySpec buildOtpSecretKey(OtpProperties otpProperties) {
        if (otpProperties == null || otpProperties.getSecret() == null || otpProperties.getSecret().isBlank()) {
            throw new IllegalStateException("app.otp.secret must be configured");
        }
        return new SecretKeySpec(otpProperties.getSecret().trim().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    private String hashOtp(String otp) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(otp.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 hashing algorithm is not available", ex);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte currentByte : bytes) {
            builder.append(String.format("%02x", currentByte));
        }
        return builder.toString();
    }

    private boolean safeEquals(String left, String right) {
        return MessageDigest.isEqual(
                String.valueOf(left).getBytes(StandardCharsets.UTF_8),
                String.valueOf(right).getBytes(StandardCharsets.UTF_8)
        );
    }

    private int parseInteger(Object value) {
        return Integer.parseInt(String.valueOf(value));
    }

    private long parseLong(Object value) {
        return Long.parseLong(String.valueOf(value));
    }

    private UUID parseUuid(String value) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Login verification challenge has expired or is invalid");
        }
    }

    public record ChallengeIssueResult(
            String challengeToken,
            String otp,
            long expiresInSeconds,
            long resendAvailableInSeconds,
            UUID userId,
            String email,
            String deviceId
    ) {
    }

    public record ChallengeContext(
            UUID userId,
            String email,
            String deviceId,
            String clientIpHash,
            String challengeToken,
            long createdAtEpochSecond,
            long resendAvailableAtEpochSecond
    ) {
    }

    public record ChallengeVerificationResult(
            UUID userId,
            String email,
            String deviceId,
            long createdAtEpochSecond,
            long expiresInSeconds
    ) {
    }
}
