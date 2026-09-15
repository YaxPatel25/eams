package com.eams.service;

import com.eams.domain.User;
import com.eams.dto.request.RegisterRequest;
import com.eams.dto.request.UpdateUserRequest;
import com.eams.dto.response.UserResponse;
import com.eams.exception.EmailAlreadyExistsException;
import com.eams.exception.ResourceNotFoundException;
import com.eams.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /** Onboards a new user. Admin-only - enforced at the controller with @PreAuthorize. */
    @Transactional
    public UserResponse onboardUser(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new EmailAlreadyExistsException(request.email());
        }

        User user = User.builder()
                .fullName(request.fullName())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(request.role())
                .enabled(true)
                .build();

        return UserResponse.from(userRepository.save(user));
    }

    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(UserResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public UserResponse getUserById(UUID id) {
        return UserResponse.from(findUserOrThrow(id));
    }

    @Transactional(readOnly = true)
    public UserResponse getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .map(UserResponse::from)
                .orElseThrow(() -> new ResourceNotFoundException("No user found with email: " + email));
    }

    /** Used both by "update my own profile" and "admin updates a user". */
    @Transactional
    public UserResponse updateUser(UUID id, UpdateUserRequest request) {
        User user = findUserOrThrow(id);
        user.setFullName(request.fullName());
        return UserResponse.from(userRepository.save(user));
    }

    /** Admin-only: flip a user's active status instead of hard-deleting the account. */
    @Transactional
    public UserResponse setEnabled(UUID id, boolean enabled) {
        User user = findUserOrThrow(id);
        user.setEnabled(enabled);
        return UserResponse.from(userRepository.save(user));
    }

    private User findUserOrThrow(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("No user found with id: " + id));
    }
}
