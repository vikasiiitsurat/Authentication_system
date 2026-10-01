package com.vikas.authsystem.repository;

import com.vikas.authsystem.entity.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    @Query("select user from User user where user.email = :email and user.deletedAt is null")
    Optional<User> findByEmail(String email);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select user from User user where user.email = :email and user.deletedAt is null")
    Optional<User> findByEmailForUpdate(String email);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select user from User user where user.id = :id and user.deletedAt is null")
    Optional<User> findByIdForUpdate(UUID id);

    @Query("select user from User user where user.id = :id and user.deletedAt is null")
    Optional<User> findActiveById(UUID id);

    java.util.List<User> findAllByDeletedAtIsNull();
}
