package com.vikas.authsystem.repository;

import com.vikas.authsystem.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findAllByUser_IdAndDeviceIdAndRevokedAtIsNull(UUID userId, String deviceId);

    List<RefreshToken> findAllByUser_IdAndRevokedAtIsNull(UUID userId);

    @Modifying
    @Query("""
            delete from RefreshToken rt
            where rt.expiryDate < :now
            """)
    void deleteAllExpiredSince(Instant now);
}
