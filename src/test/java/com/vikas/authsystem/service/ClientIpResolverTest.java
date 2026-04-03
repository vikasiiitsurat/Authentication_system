package com.vikas.authsystem.service;

import com.vikas.authsystem.config.HttpRequestProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientIpResolverTest {

    @Test
    void ignoresForwardedHeaderWhenRemoteAddressIsNotTrusted() {
        ClientIpResolver clientIpResolver = new ClientIpResolver(properties("127.0.0.1"));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("198.51.100.25");
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.10");

        assertEquals("198.51.100.25", clientIpResolver.resolve(request));
    }

    @Test
    void usesForwardedHeaderWhenRemoteAddressIsTrusted() {
        ClientIpResolver clientIpResolver = new ClientIpResolver(properties("127.0.0.1"));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getHeader("X-Forwarded-For")).thenReturn("203.0.113.10, 127.0.0.1");

        assertEquals("203.0.113.10", clientIpResolver.resolve(request));
    }

    private HttpRequestProperties properties(String... trustedProxies) {
        HttpRequestProperties properties = new HttpRequestProperties();
        properties.setTrustedProxyAddresses(List.of(trustedProxies));
        return properties;
    }
}
