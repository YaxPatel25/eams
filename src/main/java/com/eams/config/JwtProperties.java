package com.eams.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Binds the "app.jwt.*" properties from application.yml.
 * Keeping these in one place makes it obvious what governs token
 * lifetime and signing, instead of scattering @Value annotations around.
 */
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
        String secret,
        long accessTokenExpirationMs,
        long refreshTokenExpirationMs,
        String issuer
) {
}
