package com.vikas.authsystem;

import com.vikas.authsystem.config.JwtProperties;
import com.vikas.authsystem.config.LoginProtectionProperties;
import com.vikas.authsystem.config.MailProperties;
import com.vikas.authsystem.config.OtpProperties;
import com.vikas.authsystem.config.RateLimitProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
@EnableConfigurationProperties({
        JwtProperties.class,
        RateLimitProperties.class,
        LoginProtectionProperties.class,
        MailProperties.class,
        OtpProperties.class
})
public class AuthSystemApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthSystemApplication.class, args);
    }
}
