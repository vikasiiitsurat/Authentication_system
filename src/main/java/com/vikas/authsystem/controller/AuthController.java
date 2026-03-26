package com.vikas.authsystem.controller;

import com.vikas.authsystem.dto.LoginRequest;
import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.dto.LogoutRequest;
import com.vikas.authsystem.dto.ForgotPasswordRequest;
import com.vikas.authsystem.dto.PasswordChangeRequest;
import com.vikas.authsystem.dto.PasswordResetRequestResponse;
import com.vikas.authsystem.dto.RefreshTokenRequest;
import com.vikas.authsystem.dto.ResendVerificationOtpRequest;
import com.vikas.authsystem.dto.RegisterRequest;
import com.vikas.authsystem.dto.RegisterResponse;
import com.vikas.authsystem.dto.ResetPasswordRequest;
import com.vikas.authsystem.dto.VerifyEmailOtpRequest;
import com.vikas.authsystem.dto.EmailVerificationStatusResponse;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.service.AuthService;
import com.vikas.authsystem.service.RateLimiterService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Authentication entry points for registration, login, and account access.")
@Tag(name = "Token Management", description = "JWT and refresh-token lifecycle operations.")
@Tag(name = "Password Reset / OTP", description = "Password management and email verification OTP flows.")
public class AuthController {

    private final AuthService authService;
    private final RateLimiterService rateLimiterService;

    public AuthController(AuthService authService, RateLimiterService rateLimiterService) {
        this.authService = authService;
        this.rateLimiterService = rateLimiterService;
    }

    @PostMapping("/register")
    @Operation(
            summary = "Register a new account",
            description = "Creates a new user account and issues an email verification OTP. If the email exists but is still unverified, the password is rotated and a fresh OTP is sent.",
            tags = {"Authentication"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Registration accepted and verification OTP issued",
                    content = @Content(schema = @Schema(implementation = RegisterResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed or OTP issuance request is invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "409", description = "Email is already registered and verified",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "OTP generation rate limit exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest servletRequest) {
        // Controllers stay thin: extract transport-level details and delegate all business rules.
        String clientIp = extractClientIp(servletRequest);
        rateLimiterService.validateOtpGenerationRateLimit(request.email(), clientIp);
        RegisterResponse response = authService.register(request, clientIp);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    @Operation(
            summary = "Authenticate and create a session",
            description = "Validates user credentials, creates a refresh-token-backed session, and returns a JWT access token together with a refresh token.",
            tags = {"Authentication"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login succeeded",
                    content = @Content(schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "403", description = "Email verification is required before login",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "423", description = "Account is temporarily locked due to repeated failures",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "Login rate limit exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
        String clientIp = extractClientIp(servletRequest);
        rateLimiterService.validateLoginRateLimit(request.email().trim().toLowerCase(), clientIp);
        LoginResponse response = authService.login(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    @Operation(
            summary = "Rotate refresh token and issue a new access token",
            description = "Consumes a valid refresh token, rotates it, and returns a fresh access token and replacement refresh token for the same session.",
            tags = {"Token Management"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token rotation succeeded",
                    content = @Content(schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Refresh token is invalid, expired, replayed, or bound to another device",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshTokenRequest request, HttpServletRequest servletRequest) {
        String clientIp = extractClientIp(servletRequest);
        LoginResponse response = authService.refresh(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-email")
    @Operation(
            summary = "Verify account email with OTP",
            description = "Validates the email verification OTP for a pending account and marks the email address as verified.",
            tags = {"Password Reset / OTP"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Email verified or already verified",
                    content = @Content(schema = @Schema(implementation = EmailVerificationStatusResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid verification request, invalid OTP, or validation failure",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "OTP verification rate limit exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<EmailVerificationStatusResponse> verifyEmail(
            @Valid @RequestBody VerifyEmailOtpRequest request,
            HttpServletRequest servletRequest
    ) {
        String clientIp = extractClientIp(servletRequest);
        rateLimiterService.validateOtpVerificationRateLimit(request.email(), clientIp);
        EmailVerificationStatusResponse response = authService.verifyEmailOtp(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-verification-otp")
    @Operation(
            summary = "Resend email verification OTP",
            description = "Issues a new email verification OTP for an existing unverified account, subject to resend cooldown and rate-limit rules.",
            tags = {"Password Reset / OTP"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "OTP resent or request accepted without exposing account state",
                    content = @Content(schema = @Schema(implementation = EmailVerificationStatusResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "OTP resend cooldown or OTP generation rate limit exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<EmailVerificationStatusResponse> resendVerificationOtp(
            @Valid @RequestBody ResendVerificationOtpRequest request,
            HttpServletRequest servletRequest
    ) {
        String clientIp = extractClientIp(servletRequest);
        rateLimiterService.validateOtpGenerationRateLimit(request.email(), clientIp);
        EmailVerificationStatusResponse response = authService.resendVerificationOtp(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    @Operation(
            summary = "Request a password reset OTP",
            description = "Accepts a password reset request, issues a reset OTP when the account is eligible, and returns a generic response that does not disclose account existence.",
            tags = {"Password Reset / OTP"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Password reset request accepted",
                    content = @Content(schema = @Schema(implementation = PasswordResetRequestResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "Password reset request rate limit exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<PasswordResetRequestResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request,
            HttpServletRequest servletRequest
    ) {
        String clientIp = extractClientIp(servletRequest);
        rateLimiterService.validatePasswordResetRequestRateLimit(request.email(), clientIp);
        PasswordResetRequestResponse response = authService.requestPasswordReset(request, clientIp);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @PostMapping("/reset-password")
    @Operation(
            summary = "Reset password with email OTP",
            description = "Verifies the emailed password reset OTP, rotates the password, revokes all active sessions, and invalidates previously issued access tokens.",
            tags = {"Password Reset / OTP"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Password reset completed", content = @Content),
            @ApiResponse(responseCode = "400", description = "Validation failed, password reset request is invalid, or the new password reuses the current password",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "Password reset verification rate limit exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<Void> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request,
            HttpServletRequest servletRequest
    ) {
        String clientIp = extractClientIp(servletRequest);
        rateLimiterService.validatePasswordResetConfirmationRateLimit(request.email(), clientIp);
        authService.resetPassword(request, clientIp);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout")
    @Operation(
            summary = "Log out the current session",
            description = "Revokes the supplied refresh token and blacklists the current access token when an authenticated session is present.",
            tags = {"Token Management"}
    )
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Logout completed", content = @Content),
            @ApiResponse(responseCode = "400", description = "Validation failed",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Authentication is missing or the refresh token is invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<Void> logout(
            @Valid @RequestBody LogoutRequest request,
            HttpServletRequest servletRequest,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        String clientIp = extractClientIp(servletRequest);
        authService.logout(request, authenticatedUser, clientIp);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/change-password")
    @Operation(
            summary = "Change the authenticated user's password",
            description = "Changes the password for the current user, revokes all refresh tokens for that account, and blacklists the current access token and session.",
            tags = {"Password Reset / OTP"}
    )
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Password changed successfully", content = @Content),
            @ApiResponse(responseCode = "400", description = "Validation failed or new password matches the current password",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Authentication is missing or current password is invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<Void> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            HttpServletRequest servletRequest,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        String clientIp = extractClientIp(servletRequest);
        authService.changePassword(authenticatedUser, request, clientIp);
        return ResponseEntity.noContent().build();
    }

    private String extractClientIp(HttpServletRequest request) {
        // Prefer the first forwarded address when the app sits behind a trusted proxy/load balancer.
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
