package com.vikas.authsystem.repository;

import com.vikas.authsystem.entity.RefreshToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select rt
            from RefreshToken rt
            join fetch rt.user
            where rt.tokenHash = :tokenHash
            """)
    Optional<RefreshToken> findByTokenHashForUpdate(String tokenHash);

    Optional<RefreshToken> findByUser_IdAndSessionIdAndRevokedAtIsNull(UUID userId, UUID sessionId);

    List<RefreshToken> findAllByUser_IdAndDeviceIdAndRevokedAtIsNull(UUID userId, String deviceId);

    List<RefreshToken> findAllByUser_IdAndRevokedAtIsNull(UUID userId);

    List<RefreshToken> findAllByUser_IdAndRevokedAtIsNullOrderByLastUsedAtDesc(UUID userId);

    List<RefreshToken> findAllByUser_IdAndSessionId(UUID userId, UUID sessionId);

    List<RefreshToken> findAllByUser_IdAndSessionIdOrderByCreatedAtDesc(UUID userId, UUID sessionId);

    @Modifying
    @Query("""
            delete from RefreshToken rt
            where rt.expiryDate < :now
            """)
    int deleteAllExpiredSince(Instant now);
}
