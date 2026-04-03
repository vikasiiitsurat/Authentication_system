package com.vikas.authsystem.controller;

import com.vikas.authsystem.dto.AccountUnlockRequest;
import com.vikas.authsystem.dto.AccountUnlockRequestResponse;
import com.vikas.authsystem.dto.AuthenticationResponse;
import com.vikas.authsystem.dto.ForgotPasswordRequest;
import com.vikas.authsystem.dto.GlobalLogoutResponse;
import com.vikas.authsystem.dto.LoginRequest;
import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.dto.LogoutRequest;
import com.vikas.authsystem.dto.PasswordChangeRequest;
import com.vikas.authsystem.dto.PasswordResetRequestResponse;
import com.vikas.authsystem.dto.RefreshTokenRequest;
import com.vikas.authsystem.dto.ResendLoginTwoFactorRequest;
import com.vikas.authsystem.dto.ResendVerificationOtpRequest;
import com.vikas.authsystem.dto.RegisterRequest;
import com.vikas.authsystem.dto.RegisterResponse;
import com.vikas.authsystem.dto.ResetPasswordRequest;
import com.vikas.authsystem.dto.VerifyAccountUnlockRequest;
import com.vikas.authsystem.dto.EmailVerificationStatusResponse;
import com.vikas.authsystem.dto.VerifyEmailOtpRequest;
import com.vikas.authsystem.dto.VerifyLoginTwoFactorRequest;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.service.AuthService;
import com.vikas.authsystem.service.ClientIpResolver;
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
    private final ClientIpResolver clientIpResolver;

    public AuthController(AuthService authService, RateLimiterService rateLimiterService, ClientIpResolver clientIpResolver) {
        this.authService = authService;
        this.rateLimiterService = rateLimiterService;
        this.clientIpResolver = clientIpResolver;
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
        String clientIp = clientIpResolver.resolve(servletRequest);
        rateLimiterService.validateOtpGenerationRateLimit(request.email(), clientIp);
        RegisterResponse response = authService.register(request, clientIp);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    @Operation(
            summary = "Authenticate with password and optionally start a 2FA challenge",
            description = "Validates user credentials behind layered Redis-backed abuse protection. When email-based login 2FA is disabled, the endpoint returns tokens immediately. When 2FA is enabled, the endpoint sends a login OTP and returns a short-lived challenge token that must be verified before access and refresh tokens are issued.",
            tags = {"Authentication"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login succeeded or 2FA challenge issued",
                    content = @Content(schema = @Schema(implementation = AuthenticationResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid email or password",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "Source-specific login or login-2FA request rate limit exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<AuthenticationResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
        String clientIp = clientIpResolver.resolve(servletRequest);
        AuthenticationResponse response = authService.login(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-login-2fa")
    @Operation(
            summary = "Verify the OTP for a pending 2FA login challenge",
            description = "Consumes the login challenge token and 6-digit OTP sent to the user's email address. A successful verification completes authentication and returns access and refresh tokens.",
            tags = {"Authentication"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "2FA verified and login completed",
                    content = @Content(schema = @Schema(implementation = AuthenticationResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed, challenge expired, or OTP is invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "Login 2FA verification rate limit exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<AuthenticationResponse> verifyLoginTwoFactor(
            @Valid @RequestBody VerifyLoginTwoFactorRequest request,
            HttpServletRequest servletRequest
    ) {
        String clientIp = clientIpResolver.resolve(servletRequest);
        AuthenticationResponse response = authService.verifyLoginTwoFactor(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-login-2fa")
    @Operation(
            summary = "Resend the OTP for a pending 2FA login challenge",
            description = "Resends the email OTP for an active login 2FA challenge. The challenge stays bound to the original login context and is subject to cooldowns and layered request limits.",
            tags = {"Authentication"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "2FA challenge remains active and OTP is resent",
                    content = @Content(schema = @Schema(implementation = AuthenticationResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed or challenge is invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "Login 2FA resend rate limit or cooldown exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<AuthenticationResponse> resendLoginTwoFactor(
            @Valid @RequestBody ResendLoginTwoFactorRequest request,
            HttpServletRequest servletRequest
    ) {
        String clientIp = clientIpResolver.resolve(servletRequest);
        AuthenticationResponse response = authService.resendLoginTwoFactor(request, clientIp);
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
        String clientIp = clientIpResolver.resolve(servletRequest);
        LoginResponse response = authService.refresh(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-email")
    @Operation(
            summary = "Verify account email with OTP",
            description = "Validates the email verification OTP for a pending account and marks the email address as verified. Verification attempts are throttled per account, per IP, and per account+IP combination.",
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
        String clientIp = clientIpResolver.resolve(servletRequest);
        rateLimiterService.validateOtpVerificationRateLimit(request.email(), clientIp);
        EmailVerificationStatusResponse response = authService.verifyEmailOtp(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-verification-otp")
    @Operation(
            summary = "Resend email verification OTP",
            description = "Issues a new email verification OTP for an existing unverified account, subject to resend cooldown and layered rate limits across account, IP, and account+IP scopes.",
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
        String clientIp = clientIpResolver.resolve(servletRequest);
        rateLimiterService.validateOtpGenerationRateLimit(request.email(), clientIp);
        EmailVerificationStatusResponse response = authService.resendVerificationOtp(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    @Operation(
            summary = "Request a password reset OTP",
            description = "Accepts a password reset request, issues a reset OTP when the account is eligible, and returns a generic response that does not disclose account existence. Request throttling is enforced across account, IP, and account+IP scopes.",
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
        String clientIp = clientIpResolver.resolve(servletRequest);
        rateLimiterService.validatePasswordResetRequestRateLimit(request.email(), clientIp);
        PasswordResetRequestResponse response = authService.requestPasswordReset(request, clientIp);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @PostMapping("/reset-password")
    @Operation(
            summary = "Reset password with email OTP",
            description = "Verifies the emailed password reset OTP, rotates the password, revokes all active sessions, and invalidates previously issued access tokens. OTP verification is throttled across account, IP, and account+IP scopes.",
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
        String clientIp = clientIpResolver.resolve(servletRequest);
        rateLimiterService.validatePasswordResetConfirmationRateLimit(request.email(), clientIp);
        authService.resetPassword(request, clientIp);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/request-account-unlock")
    @Operation(
            summary = "Request an account unlock OTP",
            description = "Accepts an account unlock request when login protection is active, sends an unlock OTP to the account email if recovery is available, and returns a generic response that does not disclose account state.",
            tags = {"Password Reset / OTP"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Account unlock request accepted",
                    content = @Content(schema = @Schema(implementation = AccountUnlockRequestResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation failed",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "Account unlock request rate limit exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<AccountUnlockRequestResponse> requestAccountUnlock(
            @Valid @RequestBody AccountUnlockRequest request,
            HttpServletRequest servletRequest
    ) {
        String clientIp = clientIpResolver.resolve(servletRequest);
        rateLimiterService.validateAccountUnlockRequestRateLimit(request.email(), clientIp);
        AccountUnlockRequestResponse response = authService.requestAccountUnlock(request, clientIp);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    @PostMapping("/unlock-account")
    @Operation(
            summary = "Unlock account with email OTP",
            description = "Verifies the emailed account unlock OTP and clears the Redis-backed account protection state for the account and originating client context.",
            tags = {"Password Reset / OTP"}
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Account unlocked successfully", content = @Content),
            @ApiResponse(responseCode = "400", description = "Validation failed, the unlock request is invalid, or the OTP is invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "429", description = "Account unlock verification rate limit exceeded",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<Void> unlockAccount(
            @Valid @RequestBody VerifyAccountUnlockRequest request,
            HttpServletRequest servletRequest
    ) {
        String clientIp = clientIpResolver.resolve(servletRequest);
        rateLimiterService.validateAccountUnlockConfirmationRateLimit(request.email(), clientIp);
        authService.unlockAccount(request, clientIp);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout")
    @Operation(
            summary = "Log out the current session",
            description = "Revokes the authenticated session identified by the bearer access token, blacklists the current access token immediately, and tolerates missing or already-rotated refresh tokens for idempotent client logout.",
            tags = {"Token Management"}
    )
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Logout completed", content = @Content),
            @ApiResponse(responseCode = "400", description = "Validation failed",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "Authentication is missing or invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<Void> logout(
            @Valid @RequestBody(required = false) LogoutRequest request,
            HttpServletRequest servletRequest,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        String clientIp = clientIpResolver.resolve(servletRequest);
        // The request body is optional legacy input; the bearer token identifies the session to revoke.
        authService.logout(authenticatedUser, clientIp);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    @Operation(
            summary = "Globally log out the authenticated account",
            description = "Revokes every active refresh-token session for the authenticated user, blacklists the current access token and session, and writes a durable PostgreSQL invalidation timestamp so previously issued JWT access tokens are rejected across all app instances.",
            tags = {"Token Management"}
    )
    @SecurityRequirement(name = "bearerAuth")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Global logout completed",
                    content = @Content(schema = @Schema(implementation = GlobalLogoutResponse.class))),
            @ApiResponse(responseCode = "401", description = "Authentication is missing or invalid",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<GlobalLogoutResponse> logoutAll(
            HttpServletRequest servletRequest,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        String clientIp = clientIpResolver.resolve(servletRequest);
        GlobalLogoutResponse response = authService.logoutAll(authenticatedUser, clientIp);
        return ResponseEntity.ok(response);
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
        String clientIp = clientIpResolver.resolve(servletRequest);
        authService.changePassword(authenticatedUser, request, clientIp);
        return ResponseEntity.noContent().build();
    }

}
