package com.vikas.authsystem.controller;

import com.vikas.authsystem.dto.UserProfileResponse;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.service.UserQueryService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserQueryService userQueryService;

    public UserController(UserQueryService userQueryService) {
        this.userQueryService = userQueryService;
    }

    @GetMapping("/users/me")
    public UserProfileResponse me(@AuthenticationPrincipal AuthenticatedUser authenticatedUser) {
        return userQueryService.getUserProfile(authenticatedUser.getUserId());
    }

    @GetMapping("/users/{userId}")
    public UserProfileResponse userById(@PathVariable UUID userId) {
        return userQueryService.getUserProfile(userId);
    }

    @GetMapping("/admin/users")
    public List<UserProfileResponse> listUsers() {
        return userQueryService.listUsers();
    }
}
