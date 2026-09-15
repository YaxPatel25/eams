package com.eams.controller;

import com.eams.domain.Role;
import com.eams.dto.request.LoginRequest;
import com.eams.dto.request.RegisterRequest;
import com.eams.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Exercises the whole stack for real: HTTP -> Spring Security (JWT resource
 * server) -> controller -> service -> JPA/H2. This is what proves the RBAC
 * rules actually hold at the HTTP layer, not just inside a mocked service.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthAndRbacIntegrationTest {

    private static final String BOOTSTRAP_ADMIN_EMAIL = "admin@eams.local";
    private static final String BOOTSTRAP_ADMIN_PASSWORD = "Admin@12345";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void login_withBootstrapAdmin_succeedsAndReturnsTokenPair() throws Exception {
        LoginRequest login = new LoginRequest(BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void login_withWrongPassword_returns401() throws Exception {
        LoginRequest login = new LoginRequest(BOOTSTRAP_ADMIN_EMAIL, "totally-wrong-password");

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpoint_withoutToken_returns401() throws Exception {
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminOnboardsUser_thenEmployeeCanReadOwnProfileButNotAdminList() throws Exception {
        String adminAccessToken = loginAndGetAccessToken(BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_PASSWORD);

        RegisterRequest newHire = new RegisterRequest(
                "New Hire", "new.hire@example.com", "SecurePass123", Role.EMPLOYEE);

        mockMvc.perform(post("/api/users")
                        .header("Authorization", "Bearer " + adminAccessToken)
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(newHire)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("new.hire@example.com"))
                .andExpect(jsonPath("$.role").value("EMPLOYEE"));

        String employeeAccessToken = loginAndGetAccessToken("new.hire@example.com", "SecurePass123");

        // EMPLOYEE can read their own profile.
        mockMvc.perform(get("/api/users/me")
                        .header("Authorization", "Bearer " + employeeAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("new.hire@example.com"));

        // EMPLOYEE cannot list all users - that's ADMIN only.
        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + employeeAccessToken))
                .andExpect(status().isForbidden());

        // ADMIN can list all users.
        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + adminAccessToken))
                .andExpect(status().isOk());
    }

    @Test
    void refreshToken_afterLogout_isRejected() throws Exception {
        LoginRequest login = new LoginRequest(BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_PASSWORD);
        String loginResponseJson = mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String accessToken = objectMapper.readTree(loginResponseJson).get("accessToken").asText();
        String refreshToken = objectMapper.readTree(loginResponseJson).get("refreshToken").asText();

        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{\"refreshToken\":\"" + refreshToken + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    private String loginAndGetAccessToken(String email, String password) throws Exception {
        LoginRequest login = new LoginRequest(email, password);
        String responseJson = mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(objectMapper.writeValueAsString(login)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        return objectMapper.readTree(responseJson).get("accessToken").asText();
    }
}
