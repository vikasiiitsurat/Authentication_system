package com.vikas.authsystem.service;

import com.vikas.authsystem.config.OtpProperties;
import com.vikas.authsystem.exception.BadRequestException;
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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
public class PasswordResetOtpService {

    private static final Duration OTP_TTL = Duration.ofMinutes(10);
    private static final Duration RESEND_COOLDOWN = Duration.ofMinutes(1);
    private static final Duration GENERATION_LIMIT_WINDOW = Duration.ofHours(1);
    private static final Duration RESEND_LIMIT_WINDOW = Duration.ofMinutes(15);
    private static final int MAX_ATTEMPTS = 5;
    private static final int MAX_GENERATIONS_PER_WINDOW = 5;
    private static final int MAX_RESENDS_PER_WINDOW = 3;
    private static final String KEY_PREFIX = "auth:password-reset:";
    private static final String GENERATION_COUNTER_KEY_PREFIX = "auth:password-reset:generation-count:";
    private static final String RESEND_COUNTER_KEY_PREFIX = "auth:password-reset:resend-count:";
    private static final String OTP_VERSION = "1";

    private final StringRedisTemplate redisTemplate;
    private final Clock clock;
    private final SecretKeySpec otpSecretKey;

    @Autowired
    public PasswordResetOtpService(StringRedisTemplate redisTemplate, OtpProperties otpProperties) {
        this(redisTemplate, otpProperties, Clock.systemUTC());
    }

    PasswordResetOtpService(StringRedisTemplate redisTemplate, OtpProperties otpProperties, Clock clock) {
        this.redisTemplate = redisTemplate;
        this.clock = clock;
        this.otpSecretKey = buildOtpSecretKey(otpProperties);
    }

    public OtpDispatchResult requestOtp(UUID userId) {
        String key = key(userId);
        Map<Object, Object> values = redisTemplate.opsForHash().entries(key);
        if (values.isEmpty()) {
            if (!withinGenerationBudget(userId)) {
                return OtpDispatchResult.suppressed(OTP_TTL.toSeconds(), RESEND_COOLDOWN.toSeconds());
            }
            return issueOtp(userId);
        }

        OtpMetadata metadata = new OtpMetadata(
                parseLong(values.get("createdAtEpochSecond")),
                parseLong(values.get("resendAvailableAtEpochSecond")),
                String.valueOf(values.getOrDefault("otpVersion", "0"))
        );
        Instant now = Instant.now(clock);
        long expiresInSeconds = remainingSeconds(key);
        long resendAvailableInSeconds = Math.max(0, metadata.resendAvailableAtEpochSecond() - now.getEpochSecond());
        if (resendAvailableInSeconds > 0) {
            return OtpDispatchResult.suppressed(expiresInSeconds, resendAvailableInSeconds);
        }
        if (!OTP_VERSION.equals(metadata.otpVersion())) {
            if (!withinGenerationBudget(userId)) {
                return OtpDispatchResult.suppressed(OTP_TTL.toSeconds(), RESEND_COOLDOWN.toSeconds());
            }
            return issueOtp(userId);
        }
        if (!withinResendBudget(userId)) {
            return OtpDispatchResult.suppressed(expiresInSeconds, RESEND_COOLDOWN.toSeconds());
        }

        redisTemplate.opsForHash().put(
                key,
                "resendAvailableAtEpochSecond",
                String.valueOf(now.plus(RESEND_COOLDOWN).getEpochSecond())
        );
        return new OtpDispatchResult(
                true,
                generateOtp(userId, metadata.createdAtEpochSecond()),
                expiresInSeconds,
                RESEND_COOLDOWN.toSeconds()
        );
    }

    public OtpVerificationResult verifyOtp(UUID userId, String providedOtp) {
        String key = key(userId);
        HashOperations<String, Object, Object> hashOperations = redisTemplate.opsForHash();
        Map<Object, Object> values = hashOperations.entries(key);
        if (values.isEmpty()) {
            throw new BadRequestException("Password reset code has expired or is invalid");
        }

        int attempts = parseInteger(values.get("attemptCount")) + 1;
        hashOperations.put(key, "attemptCount", String.valueOf(attempts));
        if (attempts > MAX_ATTEMPTS) {
            redisTemplate.delete(key);
            throw new BadRequestException("Password reset verification attempts exceeded. Request a new code.");
        }

        String expectedHash = (String) values.get("otpHash");
        if (!MessageDigest.isEqual(hashOtp(providedOtp).getBytes(StandardCharsets.UTF_8), expectedHash.getBytes(StandardCharsets.UTF_8))) {
            throw new BadRequestException("Invalid password reset code. " + (MAX_ATTEMPTS - attempts) + " attempts remaining.");
        }

        long remainingSeconds = remainingSeconds(key);
        redisTemplate.delete(key);
        return new OtpVerificationResult(true, Math.max(0, remainingSeconds));
    }

    public long expiresInSeconds() {
        return OTP_TTL.toSeconds();
    }

    public long resendCooldownSeconds() {
        return RESEND_COOLDOWN.toSeconds();
    }

    private OtpDispatchResult issueOtp(UUID userId) {
        Instant now = Instant.now(clock);
        String otp = generateOtp(userId, now.getEpochSecond());
        String key = key(userId);
        HashOperations<String, Object, Object> hashOperations = redisTemplate.opsForHash();
        hashOperations.putAll(key, Map.of(
                "otpHash", hashOtp(otp),
                "otpVersion", OTP_VERSION,
                "attemptCount", "0",
                "createdAtEpochSecond", String.valueOf(now.getEpochSecond()),
                "resendAvailableAtEpochSecond", String.valueOf(now.plus(RESEND_COOLDOWN).getEpochSecond())
        ));
        redisTemplate.expire(key, OTP_TTL);
        return new OtpDispatchResult(true, otp, OTP_TTL.toSeconds(), RESEND_COOLDOWN.toSeconds());
    }

    private boolean withinGenerationBudget(UUID userId) {
        String key = GENERATION_COUNTER_KEY_PREFIX + userId;
        return incrementCounter(key, GENERATION_LIMIT_WINDOW) <= MAX_GENERATIONS_PER_WINDOW;
    }

    private boolean withinResendBudget(UUID userId) {
        String key = RESEND_COUNTER_KEY_PREFIX + userId;
        return incrementCounter(key, RESEND_LIMIT_WINDOW) <= MAX_RESENDS_PER_WINDOW;
    }

    private long incrementCounter(String key, Duration ttl) {
        Long count = redisTemplate.opsForValue().increment(key);
        if (count == null) {
            throw new IllegalStateException("Failed to evaluate password reset OTP limits");
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

    private String key(UUID userId) {
        return KEY_PREFIX + userId;
    }

    private String generateOtp(UUID userId, long createdAtEpochSecond) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(otpSecretKey);
            byte[] hash = mac.doFinal((userId + ":" + createdAtEpochSecond + ":password-reset").getBytes(StandardCharsets.UTF_8));
            int code = (ByteBuffer.wrap(hash, 0, Integer.BYTES).getInt() & Integer.MAX_VALUE) % 1_000_000;
            return String.format("%06d", code);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate password reset OTP", ex);
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

    private int parseInteger(Object value) {
        return Integer.parseInt(String.valueOf(value));
    }

    private long parseLong(Object value) {
        return Long.parseLong(String.valueOf(value));
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte currentByte : bytes) {
            builder.append(String.format("%02x", currentByte));
        }
        return builder.toString();
    }

    private record OtpMetadata(long createdAtEpochSecond, long resendAvailableAtEpochSecond, String otpVersion) {
    }

    public record OtpDispatchResult(boolean dispatched, String otp, long expiresInSeconds, long resendAvailableInSeconds) {

        private static OtpDispatchResult suppressed(long expiresInSeconds, long resendAvailableInSeconds) {
            return new OtpDispatchResult(false, null, Math.max(0, expiresInSeconds), Math.max(0, resendAvailableInSeconds));
        }
    }

    public record OtpVerificationResult(boolean verified, long expiresInSeconds) {
    }
}
