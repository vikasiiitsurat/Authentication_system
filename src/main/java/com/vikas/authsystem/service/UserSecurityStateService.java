package com.vikas.authsystem.service;

import com.vikas.authsystem.repository.UserRepository;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UserSecurityStateService {

    private final UserRepository userRepository;

    public UserSecurityStateService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Cacheable(cacheNames = "userSecurityState", key = "#userId")
    public UserSecurityState getSecurityState(UUID userId) {
        return userRepository.findById(userId)
                .map(user -> new UserSecurityState(
                        user.getDeletedAt() != null,
                        toEpochSecond(user.getPasswordChangedAt()),
                        toEpochSecond(user.getSessionInvalidatedAt())
                ))
                .orElse(UserSecurityState.deletedState());
    }

    @CacheEvict(cacheNames = "userSecurityState", key = "#userId")
    public void evict(UUID userId) {
        // Annotation-driven eviction.
    }

    public record UserSecurityState(
            boolean deleted,
            Long passwordChangedAtEpochSecond,
            Long sessionInvalidatedAtEpochSecond
    ) {
        private static UserSecurityState deletedState() {
            return new UserSecurityState(true, null, null);
        }
    }

    private Long toEpochSecond(java.time.Instant instant) {
        return instant == null ? null : instant.getEpochSecond();
    }
}
