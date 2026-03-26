package com.vikas.authsystem.controller;

import com.vikas.authsystem.dto.UserProfileResponse;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.service.UserQueryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api")
@Tag(name = "User Management", description = "Endpoints for retrieving the authenticated user's profile and authorized user records.")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserQueryService userQueryService;

    public UserController(UserQueryService userQueryService) {
        this.userQueryService = userQueryService;
    }

    @GetMapping("/users/me")
    @Operation(
            summary = "Get the current user's profile",
            description = "Returns the profile for the authenticated user associated with the presented JWT."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile returned",
                    content = @Content(schema = @Schema(implementation = UserProfileResponse.class))),
            @ApiResponse(responseCode = "401", description = "Authentication is required",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public UserProfileResponse me(@AuthenticationPrincipal AuthenticatedUser authenticatedUser) {
        return userQueryService.getUserProfile(authenticatedUser.getUserId());
    }

    @GetMapping("/users/{userId}")
    @Operation(
            summary = "Get a user profile by ID",
            description = "Returns a user profile when the caller is the same user or has the ADMIN role."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile returned",
                    content = @Content(schema = @Schema(implementation = UserProfileResponse.class))),
            @ApiResponse(responseCode = "401", description = "Authentication is required",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "403", description = "Caller is not allowed to access the requested profile",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public UserProfileResponse userById(
            @Parameter(description = "Unique user identifier", example = "6a6c97fb-2a07-455c-8b2f-b6d21e70f98e")
            @PathVariable UUID userId
    ) {
        return userQueryService.getUserProfile(userId);
    }

    @GetMapping("/admin/users")
    @Operation(
            summary = "List all users",
            description = "Returns every user profile in the system. This endpoint is restricted to administrators."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Users returned",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = UserProfileResponse.class)))),
            @ApiResponse(responseCode = "401", description = "Authentication is required",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "403", description = "Administrator role is required",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public List<UserProfileResponse> listUsers() {
        return userQueryService.listUsers();
    }
}
