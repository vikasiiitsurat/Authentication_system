package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.UserProfileResponse;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.exception.ResourceNotFoundException;
import com.vikas.authsystem.repository.UserRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
public class UserQueryService {

    private final UserRepository userRepository;

    public UserQueryService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.userId")
    public UserProfileResponse getUserProfile(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return toUserProfile(user);
    }

    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN')")
    public List<UserProfileResponse> listUsers() {
        return userRepository.findAll().stream()
                .map(this::toUserProfile)
                .toList();
    }

    private UserProfileResponse toUserProfile(User user) {
        return new UserProfileResponse(
                user.getId(),
                user.getEmail(),
                user.getRole(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}
