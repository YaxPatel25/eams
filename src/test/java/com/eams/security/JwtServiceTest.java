package com.eams.security;

import com.eams.config.JwtProperties;
import com.eams.domain.Role;
import com.eams.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private static final String SECRET =
            Base64.getEncoder().encodeToString("unit-test-signing-key-32-bytes-min!!".getBytes());

    private JwtService jwtService;
    private JwtProperties jwtProperties;

    @BeforeEach
    void setUp() {
        jwtProperties = new JwtProperties(SECRET, 900_000L, 604_800_000L, "eams-test");
        jwtService = new JwtService(jwtProperties);
    }

    private User sampleUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .fullName("Jane Doe")
                .email("jane.doe@example.com")
                .password("irrelevant-hash")
                .role(Role.EMPLOYEE)
                .enabled(true)
                .build();
    }

    @Test
    void generateAccessToken_containsSubjectAndRoleClaim() {
        User user = sampleUser();

        String token = jwtService.generateAccessToken(user);

        Claims claims = parseClaims(token);
        assertThat(claims.getSubject()).isEqualTo(user.getEmail());
        assertThat(claims.get("role", String.class)).isEqualTo("EMPLOYEE");
        assertThat(claims.get("type", String.class)).isEqualTo("access");
        assertThat(claims.getIssuer()).isEqualTo("eams-test");
    }

    @Test
    void generateRefreshToken_isMarkedAsRefreshType() {
        User user = sampleUser();

        String token = jwtService.generateRefreshToken(user);

        Claims claims = parseClaims(token);
        assertThat(claims.get("type", String.class)).isEqualTo("refresh");
    }

    @Test
    void generateAccessToken_expiryIsAfterIssuedAt() {
        User user = sampleUser();

        String token = jwtService.generateAccessToken(user);

        Claims claims = parseClaims(token);
        assertThat(claims.getExpiration()).isAfter(claims.getIssuedAt());
    }

    @Test
    void getAccessTokenExpirySeconds_convertsMillisecondsCorrectly() {
        assertThat(jwtService.getAccessTokenExpirySeconds()).isEqualTo(900L);
    }

    private Claims parseClaims(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(SECRET));
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
