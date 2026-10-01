package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.TwoFactorStatusResponse;
import com.vikas.authsystem.dto.TwoFactorUpdateRequest;
import com.vikas.authsystem.entity.AuditAction;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.exception.BadRequestException;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.repository.UserRepository;
import com.vikas.authsystem.security.AuthenticatedUser;
import io.micrometer.core.instrument.Timer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;

@Service
public class TwoFactorManagementService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginTwoFactorChallengeService loginTwoFactorChallengeService;
    private final AuditService auditService;
    private final AuthMetricsService authMetricsService;
    private final Clock clock;

    public TwoFactorManagementService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            LoginTwoFactorChallengeService loginTwoFactorChallengeService,
            AuditService auditService,
            AuthMetricsService authMetricsService,
            Clock clock
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.loginTwoFactorChallengeService = loginTwoFactorChallengeService;
        this.auditService = auditService;
        this.authMetricsService = authMetricsService;
        this.clock = clock;
    }

    @Transactional
    public TwoFactorStatusResponse enable(AuthenticatedUser authenticatedUser, TwoFactorUpdateRequest request, String clientIp) {
        return updateTwoFactor(authenticatedUser, request, clientIp, true);
    }

    @Transactional
    public TwoFactorStatusResponse disable(AuthenticatedUser authenticatedUser, TwoFactorUpdateRequest request, String clientIp) {
        return updateTwoFactor(authenticatedUser, request, clientIp, false);
    }

    private TwoFactorStatusResponse updateTwoFactor(
            AuthenticatedUser authenticatedUser,
            TwoFactorUpdateRequest request,
            String clientIp,
            boolean enable
    ) {
        Timer.Sample sample = authMetricsService.startTimer();
        String operation = enable ? "enable_two_factor" : "disable_two_factor";
        String outcome = "error";
        try {
            if (authenticatedUser == null) {
                throw new UnauthorizedException("Authentication is required");
            }

            User user = userRepository.findByIdForUpdate(authenticatedUser.getUserId())
                    .orElseThrow(() -> new UnauthorizedException("Authenticated user not found"));

            if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
                outcome = "invalid_current_password";
                auditService.recordEvent(
                        enable ? AuditAction.TWO_FACTOR_ENABLE_FAILED : AuditAction.TWO_FACTOR_DISABLE_FAILED,
                        user.getId(),
                        request.deviceId(),
                        clientIp
                );
                throw new UnauthorizedException("Current password is invalid");
            }

            if (enable && !user.isEmailVerified()) {
                outcome = "email_not_verified";
                auditService.recordEvent(AuditAction.TWO_FACTOR_ENABLE_FAILED, user.getId(), request.deviceId(), clientIp);
                throw new BadRequestException("Two-factor authentication requires a verified email address");
            }

            if (enable) {
                if (user.isTwoFactorEnabled()) {
                    outcome = "already_enabled";
                    return new TwoFactorStatusResponse(true, user.getTwoFactorEnabledAt(), "Two-factor authentication is already enabled");
                }
                Instant enabledAt = Instant.now(clock);
                user.setTwoFactorEnabled(true);
                user.setTwoFactorEnabledAt(enabledAt);
                userRepository.save(user);
                auditService.recordEvent(AuditAction.TWO_FACTOR_ENABLED, user.getId(), request.deviceId(), clientIp);
                outcome = "success";
                return new TwoFactorStatusResponse(true, enabledAt, "Two-factor authentication is enabled");
            }

            if (!user.isTwoFactorEnabled()) {
                outcome = "already_disabled";
                return new TwoFactorStatusResponse(false, null, "Two-factor authentication is already disabled");
            }

            user.setTwoFactorEnabled(false);
            user.setTwoFactorEnabledAt(null);
            userRepository.save(user);
            loginTwoFactorChallengeService.invalidateChallenge(user.getId());
            auditService.recordEvent(AuditAction.TWO_FACTOR_DISABLED, user.getId(), request.deviceId(), clientIp);
            outcome = "success";
            return new TwoFactorStatusResponse(false, null, "Two-factor authentication is disabled");
        } finally {
            authMetricsService.recordOperation(operation, outcome, sample);
        }
    }
}
