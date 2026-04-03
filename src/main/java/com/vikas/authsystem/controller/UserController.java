package com.vikas.authsystem.controller;

import com.vikas.authsystem.dto.DeleteAccountRequest;
import com.vikas.authsystem.dto.TwoFactorStatusResponse;
import com.vikas.authsystem.dto.TwoFactorUpdateRequest;
import com.vikas.authsystem.dto.UserProfileResponse;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.service.AccountManagementService;
import com.vikas.authsystem.service.TwoFactorManagementService;
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
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api")
@Tag(name = "User Management", description = "Endpoints for retrieving the authenticated user's profile and authorized user records.")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserQueryService userQueryService;
    private final AccountManagementService accountManagementService;
    private final TwoFactorManagementService twoFactorManagementService;

    public UserController(
            UserQueryService userQueryService,
            AccountManagementService accountManagementService,
            TwoFactorManagementService twoFactorManagementService
    ) {
        this.userQueryService = userQueryService;
        this.accountManagementService = accountManagementService;
        this.twoFactorManagementService = twoFactorManagementService;
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

    @PostMapping("/users/me/delete-account")
    @Operation(
            summary = "Soft-delete the authenticated account",
            description = "Soft-deletes the authenticated user account after verifying the current password and typed email confirmation. The operation revokes all active refresh-token sessions, blacklists the current access token and session, marks the account as deleted, and tombstones the stored email so the original address can be reused safely."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Account deleted", content = @Content),
            @ApiResponse(responseCode = "400", description = "Validation failed or the confirmation email does not match the authenticated account",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Authentication is required or current password is invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<Void> deleteMyAccount(
            @Valid @RequestBody DeleteAccountRequest request,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            HttpServletRequest servletRequest
    ) {
        accountManagementService.deleteAuthenticatedAccount(
                authenticatedUser,
                request,
                extractClientIp(servletRequest)
        );
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/users/me/2fa/enable")
    @Operation(
            summary = "Enable email-based login 2FA for the authenticated account",
            description = "Turns on email OTP verification during login for the current account after confirming the current password. The current profile and future logins will reflect the updated 2FA state."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "2FA enabled or already enabled",
                    content = @Content(schema = @Schema(implementation = TwoFactorStatusResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed or the account is not eligible for 2FA enablement",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Authentication is required or current password is invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<TwoFactorStatusResponse> enableTwoFactor(
            @Valid @RequestBody TwoFactorUpdateRequest request,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            HttpServletRequest servletRequest
    ) {
        TwoFactorStatusResponse response = twoFactorManagementService.enable(
                authenticatedUser,
                request,
                extractClientIp(servletRequest)
        );
        return ResponseEntity.ok(response);
    }

    @PostMapping("/users/me/2fa/disable")
    @Operation(
            summary = "Disable email-based login 2FA for the authenticated account",
            description = "Turns off email OTP verification during login for the current account after confirming the current password. Any pending login 2FA challenge is invalidated."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "2FA disabled or already disabled",
                    content = @Content(schema = @Schema(implementation = TwoFactorStatusResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Authentication is required or current password is invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<TwoFactorStatusResponse> disableTwoFactor(
            @Valid @RequestBody TwoFactorUpdateRequest request,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            HttpServletRequest servletRequest
    ) {
        TwoFactorStatusResponse response = twoFactorManagementService.disable(
                authenticatedUser,
                request,
                extractClientIp(servletRequest)
        );
        return ResponseEntity.ok(response);
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

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
