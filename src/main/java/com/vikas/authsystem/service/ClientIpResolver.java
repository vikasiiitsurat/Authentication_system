package com.vikas.authsystem.service;

import com.vikas.authsystem.config.HttpRequestProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class ClientIpResolver {

    private final Set<String> trustedProxyAddresses;

    public ClientIpResolver(HttpRequestProperties httpRequestProperties) {
        this.trustedProxyAddresses = httpRequestProperties.getTrustedProxyAddresses().stream()
                .map(value -> value == null ? "" : value.trim())
                .filter(value -> !value.isBlank())
                .collect(Collectors.toUnmodifiableSet());
    }

    public String resolve(HttpServletRequest request) {
        String remoteAddress = normalize(request.getRemoteAddr());
        if (!trustedProxyAddresses.contains(remoteAddress)) {
            return remoteAddress;
        }

        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor == null || forwardedFor.isBlank()) {
            return remoteAddress;
        }

        String firstForwardedAddress = forwardedFor.split(",")[0];
        String resolvedAddress = normalize(firstForwardedAddress);
        return resolvedAddress.isBlank() ? remoteAddress : resolvedAddress;
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
