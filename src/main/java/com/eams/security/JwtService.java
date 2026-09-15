package com.eams.security;

import com.eams.config.JwtProperties;
import com.eams.domain.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Everything to do with MINTING a signed JWT lives here.
 * Validation/parsing of incoming tokens on protected requests is delegated
 * to Spring Security's OAuth2 Resource Server support (see SecurityConfig's
 * JwtDecoder bean) - that's the "OAuth2 + JWT" half of the stack described
 * in the project brief. This class is the "we act as our own authorization
 * server" half: it issues the tokens that the resource-server side later
 * validates on every request.
 */
@Service
public class JwtService {

    private static final String CLAIM_ROLE = "role";
    private static final String CLAIM_TOKEN_TYPE = "type";
    private static final String TOKEN_TYPE_ACCESS = "access";
    private static final String TOKEN_TYPE_REFRESH = "refresh";

    private final JwtProperties jwtProperties;
    private final SecretKey signingKey;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.signingKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(jwtProperties.secret()));
    }

    /** Short-lived token sent on every API call, validated by the resource server. */
    public String generateAccessToken(User user) {
        return buildToken(user, jwtProperties.accessTokenExpirationMs(), TOKEN_TYPE_ACCESS);
    }

    /**
     * Longer-lived token used only to obtain a new access token.
     * Its raw value is also persisted (see RefreshToken entity) so it can be
     * revoked server-side on logout, independent of its expiry.
     */
    public String generateRefreshToken(User user) {
        return buildToken(user, jwtProperties.refreshTokenExpirationMs(), TOKEN_TYPE_REFRESH);
    }

    public long getAccessTokenExpirySeconds() {
        return jwtProperties.accessTokenExpirationMs() / 1000;
    }

    public Instant refreshTokenExpiryInstant() {
        return Instant.now().plusMillis(jwtProperties.refreshTokenExpirationMs());
    }

    private String buildToken(User user, long expirationMs, String tokenType) {
        Instant now = Instant.now();
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getEmail())
                .issuer(jwtProperties.issuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(expirationMs)))
                .claim(CLAIM_ROLE, user.getRole().name())
                .claim(CLAIM_TOKEN_TYPE, tokenType)
                .signWith(signingKey)
                .compact();
    }
}
