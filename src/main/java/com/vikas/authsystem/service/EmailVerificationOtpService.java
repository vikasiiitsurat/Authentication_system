package com.vikas.authsystem.service;

import com.vikas.authsystem.exception.BadRequestException;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
public class EmailVerificationOtpService {

    private static final Duration OTP_TTL = Duration.ofMinutes(3);
    private static final Duration RESEND_COOLDOWN = Duration.ofSeconds(30);
    private static final Duration GENERATION_LIMIT_WINDOW = Duration.ofHours(1);
    private static final Duration RESEND_LIMIT_WINDOW = Duration.ofMinutes(15);
    private static final int MAX_ATTEMPTS = 5;
    private static final int MAX_GENERATIONS_PER_WINDOW = 5;
    private static final int MAX_RESENDS_PER_WINDOW = 3;
    private static final String KEY_PREFIX = "auth:email-verification:";
    private static final String GENERATION_COUNTER_KEY_PREFIX = "auth:email-verification:generation-count:";
    private static final String RESEND_COUNTER_KEY_PREFIX = "auth:email-verification:resend-count:";
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
    private final SecureRandom secureRandom = new SecureRandom();

    public EmailVerificationOtpService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public OtpIssueResult issueOtp(UUID userId) {
        enforceGenerationBudget(userId);
        String otp = generateOtp();
        Instant now = Instant.now();
        String key = key(userId);
        HashOperations<String, Object, Object> hashOperations = redisTemplate.opsForHash();
        hashOperations.putAll(key, Map.of(
                "otpHash", hashOtp(otp),
                "attemptCount", "0",
                "createdAtEpochSecond", String.valueOf(now.getEpochSecond()),
                "resendAvailableAtEpochSecond", String.valueOf(now.plus(RESEND_COOLDOWN).getEpochSecond())
        ));
        redisTemplate.expire(key, OTP_TTL);
        return new OtpIssueResult(otp, OTP_TTL.toSeconds(), RESEND_COOLDOWN.toSeconds());
    }

    public OtpIssueResult reissueOtp(UUID userId) {
        String key = key(userId);
        Map<Object, Object> values = redisTemplate.opsForHash().entries(key);
        if (values.isEmpty()) {
            return issueOtp(userId);
        }
        OtpMetadata metadata = new OtpMetadata(parseLong(values.get("resendAvailableAtEpochSecond")));
        long resendAvailableInSeconds = Math.max(0, metadata.resendAvailableAtEpochSecond() - Instant.now().getEpochSecond());
        if (resendAvailableInSeconds > 0) {
            throw new BadRequestException("OTP can be resent in " + resendAvailableInSeconds + " seconds");
        }
        enforceResendBudget(userId);
        return issueOtp(userId);
    }

    public OtpVerificationResult verifyOtp(UUID userId, String providedOtp) {
        String key = key(userId);
        HashOperations<String, Object, Object> hashOperations = redisTemplate.opsForHash();
        Map<Object, Object> values = hashOperations.entries(key);
        if (values.isEmpty()) {
            throw new BadRequestException("OTP has expired or is invalid");
        }

        int attempts = parseInteger(values.get("attemptCount")) + 1;
        hashOperations.put(key, "attemptCount", String.valueOf(attempts));
        if (attempts > MAX_ATTEMPTS) {
            redisTemplate.delete(key);
            throw new BadRequestException("OTP verification attempts exceeded. Request a new OTP.");
        }

        String expectedHash = (String) values.get("otpHash");
        if (!MessageDigest.isEqual(hashOtp(providedOtp).getBytes(StandardCharsets.UTF_8), expectedHash.getBytes(StandardCharsets.UTF_8))) {
            throw new BadRequestException("Invalid OTP. " + (MAX_ATTEMPTS - attempts) + " attempts remaining.");
        }

        long remainingSeconds = remainingSeconds(key);
        redisTemplate.delete(key);
        return new OtpVerificationResult(true, Math.max(0, remainingSeconds));
    }

    public OtpStatus status(UUID userId) {
        OtpMetadata metadata = getRequiredMetadata(userId);
        long now = Instant.now().getEpochSecond();
        long expiresInSeconds = remainingSeconds(key(userId));
        long resendAvailableInSeconds = Math.max(0, metadata.resendAvailableAtEpochSecond() - now);
        return new OtpStatus(expiresInSeconds, resendAvailableInSeconds);
    }

    private OtpMetadata getRequiredMetadata(UUID userId) {
        String key = key(userId);
        Map<Object, Object> values = redisTemplate.opsForHash().entries(key);
        if (values.isEmpty()) {
            throw new BadRequestException("OTP has expired or is unavailable. Request a new OTP.");
        }
        return new OtpMetadata(parseLong(values.get("resendAvailableAtEpochSecond")));
    }

    private long remainingSeconds(String key) {
        Long ttl = redisTemplate.getExpire(key);
        return ttl == null || ttl < 0 ? 0 : ttl;
    }

    private String key(UUID userId) {
        return KEY_PREFIX + userId;
    }

    private void enforceGenerationBudget(UUID userId) {
        long count = incrementCounter(generationCounterKey(userId), GENERATION_LIMIT_WINDOW);
        if (count > MAX_GENERATIONS_PER_WINDOW) {
            throw new BadRequestException("OTP generation limit reached. Please try again later.");
        }
    }

    private void enforceResendBudget(UUID userId) {
        long count = incrementCounter(resendCounterKey(userId), RESEND_LIMIT_WINDOW);
        if (count > MAX_RESENDS_PER_WINDOW) {
            throw new BadRequestException("Resend limit reached. Please wait before requesting another OTP.");
        }
    }

    private long incrementCounter(String key, Duration ttl) {
        Long count = redisTemplate.execute(
                INCREMENT_WITH_TTL_SCRIPT,
                java.util.List.of(key),
                String.valueOf(ttl.toSeconds())
        );
        if (count == null) {
            throw new IllegalStateException("Failed to evaluate OTP limit");
        }
        return count;
    }

    private String generationCounterKey(UUID userId) {
        return GENERATION_COUNTER_KEY_PREFIX + userId;
    }

    private String resendCounterKey(UUID userId) {
        return RESEND_COUNTER_KEY_PREFIX + userId;
    }

    private String generateOtp() {
        return String.format("%06d", secureRandom.nextInt(1_000_000));
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

    private record OtpMetadata(long resendAvailableAtEpochSecond) {
    }

    public record OtpIssueResult(String otp, long expiresInSeconds, long resendAvailableInSeconds) {
    }

    public record OtpVerificationResult(boolean verified, long expiresInSeconds) {
    }

    public record OtpStatus(long expiresInSeconds, long resendAvailableInSeconds) {
    }
}
