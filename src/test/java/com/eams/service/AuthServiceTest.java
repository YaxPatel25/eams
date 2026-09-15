package com.eams.service;

import com.eams.domain.Role;
import com.eams.domain.User;
import com.eams.dto.request.LoginRequest;
import com.eams.dto.response.AuthResponse;
import com.eams.exception.InvalidRefreshTokenException;
import com.eams.repository.UserRepository;
import com.eams.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private Authentication authentication;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(authenticationManager, jwtService, refreshTokenService, userRepository);
    }

    private User sampleUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .fullName("Jane Doe")
                .email("jane.doe@example.com")
                .password("hashed")
                .role(Role.EMPLOYEE)
                .enabled(true)
                .build();
    }

    @Test
    void login_returnsTokenPairOnSuccessfulAuthentication() {
        User user = sampleUser();
        LoginRequest request = new LoginRequest(user.getEmail(), "plainPassword");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(user);
        when(jwtService.generateAccessToken(user)).thenReturn("access-token-123");
        when(refreshTokenService.issueFor(user)).thenReturn("refresh-token-456");
        when(jwtService.getAccessTokenExpirySeconds()).thenReturn(900L);

        AuthResponse response = authService.login(request);

        assertThat(response.accessToken()).isEqualTo("access-token-123");
        assertThat(response.refreshToken()).isEqualTo("refresh-token-456");
        assertThat(response.expiresInSeconds()).isEqualTo(900L);
        assertThat(response.tokenType()).isEqualTo("Bearer");
    }

    @Test
    void login_propagatesBadCredentialsException() {
        LoginRequest request = new LoginRequest("jane.doe@example.com", "wrongPassword");
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(BadCredentialsException.class);

        verifyNoInteractions(jwtService, refreshTokenService);
    }

    @Test
    void refresh_rotatesOldTokenAndIssuesNewPair() {
        User user = sampleUser();
        String oldRefreshToken = "old-refresh-token";

        when(refreshTokenService.validateAndGetUser(oldRefreshToken)).thenReturn(user);
        when(jwtService.generateAccessToken(user)).thenReturn("new-access-token");
        when(refreshTokenService.issueFor(user)).thenReturn("new-refresh-token");
        when(jwtService.getAccessTokenExpirySeconds()).thenReturn(900L);

        AuthResponse response = authService.refresh(oldRefreshToken);

        verify(refreshTokenService).revoke(oldRefreshToken);
        assertThat(response.accessToken()).isEqualTo("new-access-token");
        assertThat(response.refreshToken()).isEqualTo("new-refresh-token");
    }

    @Test
    void refresh_propagatesInvalidRefreshTokenException() {
        when(refreshTokenService.validateAndGetUser("bad-token"))
                .thenThrow(new InvalidRefreshTokenException("Refresh token has expired"));

        assertThatThrownBy(() -> authService.refresh("bad-token"))
                .isInstanceOf(InvalidRefreshTokenException.class);

        verify(refreshTokenService, never()).revoke(any());
    }

    @Test
    void logout_revokesAllTokensForResolvedUser() {
        User user = sampleUser();
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));

        authService.logout(user.getEmail());

        verify(refreshTokenService).revokeAllForUser(user);
    }
}
