package com.eams.controller;

import com.eams.dto.request.RegisterRequest;
import com.eams.dto.request.UpdateUserRequest;
import com.eams.dto.response.UserResponse;
import com.eams.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "User Management", description = "Onboarding and user management (RBAC: ADMIN vs EMPLOYEE)")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Onboard a new user (ADMIN only)")
    public ResponseEntity<UserResponse> onboardUser(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.onboardUser(request));
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "List all users (ADMIN only)")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get any user by id (ADMIN only)")
    public ResponseEntity<UserResponse> getUserById(@PathVariable UUID id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Activate or deactivate a user's account (ADMIN only)")
    public ResponseEntity<UserResponse> setUserEnabled(@PathVariable UUID id, @RequestParam boolean enabled) {
        return ResponseEntity.ok(userService.setEnabled(id, enabled));
    }

    @GetMapping("/me")
    @Operation(summary = "Get the currently authenticated user's own profile")
    public ResponseEntity<UserResponse> getMyProfile(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(userService.getUserByEmail(jwt.getSubject()));
    }

    @PutMapping("/me")
    @Operation(summary = "Update the currently authenticated user's own profile")
    public ResponseEntity<UserResponse> updateMyProfile(@AuthenticationPrincipal Jwt jwt,
                                                          @Valid @RequestBody UpdateUserRequest request) {
        UUID myId = userService.getUserByEmail(jwt.getSubject()).id();
        return ResponseEntity.ok(userService.updateUser(myId, request));
    }
}
