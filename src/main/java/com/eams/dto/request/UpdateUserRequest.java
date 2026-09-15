package com.eams.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Deliberately does NOT include email or role:
 * - email is the login identifier, changing it is a bigger workflow than this project needs
 * - role changes are an admin-only, security-sensitive action -> see UserController#changeRole
 */
public record UpdateUserRequest(

        @NotBlank(message = "Full name is required")
        String fullName
) {
}
