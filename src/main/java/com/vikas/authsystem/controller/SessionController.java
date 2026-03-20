package com.vikas.authsystem.controller;

import com.vikas.authsystem.dto.SessionBulkRevocationResponse;
import com.vikas.authsystem.dto.SessionResponse;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    private final SessionService sessionService;

    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @GetMapping
    public List<SessionResponse> listSessions(@AuthenticationPrincipal AuthenticatedUser authenticatedUser) {
        return sessionService.listSessions(authenticatedUser);
    }

    @DeleteMapping("/{sessionId}")
    public ResponseEntity<Void> revokeSession(
            @PathVariable UUID sessionId,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            HttpServletRequest request
    ) {
        sessionService.revokeSession(authenticatedUser, sessionId, extractClientIp(request));
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/others")
    public ResponseEntity<SessionBulkRevocationResponse> revokeOtherSessions(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            HttpServletRequest request
    ) {
        SessionBulkRevocationResponse response = sessionService.revokeOtherSessions(
                authenticatedUser,
                extractClientIp(request)
        );
        return ResponseEntity.ok(response);
    }

    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
