package com.eams.service;

import com.eams.domain.RefreshToken;
import com.eams.domain.User;
import com.eams.exception.InvalidRefreshTokenException;
import com.eams.repository.RefreshTokenRepository;
import com.eams.security.JwtService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JwtService jwtService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
    }

    /** Issues and stores a brand-new refresh token for this user. */
    @Transactional
    public String issueFor(User user) {
        String token = jwtService.generateRefreshToken(user);
        RefreshToken entity = RefreshToken.builder()
                .token(token)
                .user(user)
                .expiresAt(jwtService.refreshTokenExpiryInstant())
                .revoked(false)
                .build();
        refreshTokenRepository.save(entity);
        return token;
    }

    /**
     * Validates a presented refresh token (exists, not revoked, not expired)
     * and returns its owner. Throws otherwise - callers should treat this
     * as "log the user out and make them sign in again".
     */
    @Transactional(readOnly = true)
    public User validateAndGetUser(String rawToken) {
        RefreshToken stored = refreshTokenRepository.findByToken(rawToken)
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token not recognized"));

        if (stored.isRevoked()) {
            throw new InvalidRefreshTokenException("Refresh token has been revoked");
        }
        if (stored.isExpired()) {
            throw new InvalidRefreshTokenException("Refresh token has expired");
        }
        return stored.getUser();
    }

    /** Revokes a single presented token - used during token refresh (rotation). */
    @Transactional
    public void revoke(String rawToken) {
        refreshTokenRepository.findByToken(rawToken).ifPresent(rt -> {
            rt.setRevoked(true);
            refreshTokenRepository.save(rt);
        });
    }

    /** Revokes every active token for a user - used on explicit logout. */
    @Transactional
    public void revokeAllForUser(User user) {
        refreshTokenRepository.revokeAllForUser(user);
    }
}
