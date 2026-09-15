package com.eams.service;

import com.eams.domain.User;
import com.eams.dto.request.LoginRequest;
import com.eams.dto.response.AuthResponse;
import com.eams.exception.ResourceNotFoundException;
import com.eams.repository.UserRepository;
import com.eams.security.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Handles session authentication: turning a (email, password) pair into a
 * token pair, and turning a refresh token into a new access token.
 * User CRUD/onboarding lives in UserService instead - this class is only
 * about issuing and rotating tokens.
 */
@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;

    public AuthService(AuthenticationManager authenticationManager,
                        JwtService jwtService,
                        RefreshTokenService refreshTokenService,
                        UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.userRepository = userRepository;
    }

    public AuthResponse login(LoginRequest request) {
        // Delegates to DaoAuthenticationProvider -> CustomUserDetailsService + PasswordEncoder.
        // Throws BadCredentialsException (mapped by GlobalExceptionHandler) on failure.
        var authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );
        User user = (User) authentication.getPrincipal();

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = refreshTokenService.issueFor(user);

        return AuthResponse.of(accessToken, refreshToken, jwtService.getAccessTokenExpirySeconds());
    }

    /**
     * Rotates the refresh token: the old one is revoked and a new pair is
     * issued. Rotation limits the damage if a refresh token is ever stolen,
     * since a reused/old token stops working the moment the real client
     * rotates it.
     */
    public AuthResponse refresh(String presentedRefreshToken) {
        User user = refreshTokenService.validateAndGetUser(presentedRefreshToken);
        refreshTokenService.revoke(presentedRefreshToken);

        String newAccessToken = jwtService.generateAccessToken(user);
        String newRefreshToken = refreshTokenService.issueFor(user);

        return AuthResponse.of(newAccessToken, newRefreshToken, jwtService.getAccessTokenExpirySeconds());
    }

    @Transactional
    public void logout(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("No user found with email: " + email));
        refreshTokenService.revokeAllForUser(user);
    }
}
