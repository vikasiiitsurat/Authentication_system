package com.vikas.authsystem.exception;

import com.vikas.authsystem.dto.ApiErrorResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void tooManyRequestsResponsesIncludeRetryAfterHeaderWhenPresent() {
        TooManyRequestsException exception = new TooManyRequestsException(
                "OTP can be resent in 30 seconds.",
                30
        );

        ResponseEntity<ApiErrorResponse> response = handler.handleTooManyRequests(exception);

        assertEquals(HttpStatus.TOO_MANY_REQUESTS, response.getStatusCode());
        assertEquals("30", response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER));
        assertNotNull(response.getBody());
        assertEquals("OTP can be resent in 30 seconds.", response.getBody().message());
    }
}
