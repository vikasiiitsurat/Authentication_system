package com.vikas.authsystem.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "app.http")
public class HttpRequestProperties {

    private List<String> trustedProxyAddresses = new ArrayList<>();

    public List<String> getTrustedProxyAddresses() {
        return trustedProxyAddresses;
    }

    public void setTrustedProxyAddresses(List<String> trustedProxyAddresses) {
        this.trustedProxyAddresses = trustedProxyAddresses == null ? new ArrayList<>() : trustedProxyAddresses;
    }
}
