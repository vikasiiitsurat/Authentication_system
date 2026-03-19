package com.vikas.authsystem.controller;

import com.vikas.authsystem.dto.LoginRequest;
import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.dto.LogoutRequest;
import com.vikas.authsystem.dto.PasswordChangeRequest;
import com.vikas.authsystem.dto.RefreshTokenRequest;
import com.vikas.authsystem.dto.ResendVerificationOtpRequest;
import com.vikas.authsystem.dto.RegisterRequest;
import com.vikas.authsystem.dto.RegisterResponse;
import com.vikas.authsystem.dto.VerifyEmailOtpRequest;
import com.vikas.authsystem.dto.EmailVerificationStatusResponse;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.service.AuthService;
import com.vikas.authsystem.service.RateLimiterService;
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
public class AuthController {

    private final AuthService authService;
    private final RateLimiterService rateLimiterService;

    public AuthController(AuthService authService, RateLimiterService rateLimiterService) {
        this.authService = authService;
        this.rateLimiterService = rateLimiterService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest servletRequest) {
        // Controllers stay thin: extract transport-level details and delegate all business rules.
        String clientIp = extractClientIp(servletRequest);
        rateLimiterService.validateOtpGenerationRateLimit(request.email(), clientIp);
        RegisterResponse response = authService.register(request, clientIp);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
        String clientIp = extractClientIp(servletRequest);
        rateLimiterService.validateLoginRateLimit(request.email().trim().toLowerCase(), clientIp);
        LoginResponse response = authService.login(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshTokenRequest request, HttpServletRequest servletRequest) {
        String clientIp = extractClientIp(servletRequest);
        LoginResponse response = authService.refresh(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-email")
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
    public ResponseEntity<EmailVerificationStatusResponse> resendVerificationOtp(
            @Valid @RequestBody ResendVerificationOtpRequest request,
            HttpServletRequest servletRequest
    ) {
        String clientIp = extractClientIp(servletRequest);
        rateLimiterService.validateOtpGenerationRateLimit(request.email(), clientIp);
        EmailVerificationStatusResponse response = authService.resendVerificationOtp(request, clientIp);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
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
    public ResponseEntity<Void> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            HttpServletRequest servletRequest,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser
    ) {
        String clientIp = extractClientIp(servletRequest);
        authService.changePassword(authenticatedUser.getUserId(), request, clientIp);
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
