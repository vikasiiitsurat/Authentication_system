package com.vikas.authsystem.controller;

import com.vikas.authsystem.dto.SessionBulkRevocationResponse;
import com.vikas.authsystem.dto.SessionResponse;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.service.ClientIpResolver;
import com.vikas.authsystem.service.SessionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Token Management", description = "Operations for listing and revoking refresh-token-backed user sessions.")
@SecurityRequirement(name = "bearerAuth")
public class SessionController {

    private final SessionService sessionService;
    private final ClientIpResolver clientIpResolver;

    public SessionController(SessionService sessionService, ClientIpResolver clientIpResolver) {
        this.sessionService = sessionService;
        this.clientIpResolver = clientIpResolver;
    }

    @GetMapping
    @Operation(
            summary = "List active sessions",
            description = "Returns the active refresh-token-backed sessions for the authenticated user, marking which session is the current one."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Active sessions returned",
                    content = @Content(array = @ArraySchema(schema = @Schema(implementation = SessionResponse.class)))),
            @ApiResponse(responseCode = "401", description = "Authentication is required",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public List<SessionResponse> listSessions(@AuthenticationPrincipal AuthenticatedUser authenticatedUser) {
        return sessionService.listSessions(authenticatedUser);
    }

    @DeleteMapping("/{sessionId}")
    @Operation(
            summary = "Revoke a specific session",
            description = "Revokes the selected session for the authenticated user. If the current session is revoked, the current access token and session are blacklisted immediately."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Session revoked", content = @Content),
            @ApiResponse(responseCode = "401", description = "Authentication is required",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "Session not found",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<Void> revokeSession(
            @Parameter(description = "Session identifier to revoke", example = "9f4af534-4e16-4f80-b50a-0dd547f1de4d")
            @PathVariable UUID sessionId,
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            HttpServletRequest request
    ) {
        sessionService.revokeSession(authenticatedUser, sessionId, clientIpResolver.resolve(request));
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/others")
    @Operation(
            summary = "Revoke all other sessions",
            description = "Revokes every active session for the authenticated user except the one represented by the current access token."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Other sessions revoked",
                    content = @Content(schema = @Schema(implementation = SessionBulkRevocationResponse.class))),
            @ApiResponse(responseCode = "401", description = "Authentication is required",
                    content = @Content(schema = @Schema(implementation = com.vikas.authsystem.dto.ApiErrorResponse.class)))
    })
    public ResponseEntity<SessionBulkRevocationResponse> revokeOtherSessions(
            @AuthenticationPrincipal AuthenticatedUser authenticatedUser,
            HttpServletRequest request
    ) {
        SessionBulkRevocationResponse response = sessionService.revokeOtherSessions(
                authenticatedUser,
                clientIpResolver.resolve(request)
        );
        return ResponseEntity.ok(response);
    }
}
