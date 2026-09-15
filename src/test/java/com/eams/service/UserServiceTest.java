package com.eams.service;

import com.eams.domain.Role;
import com.eams.domain.User;
import com.eams.dto.request.RegisterRequest;
import com.eams.dto.request.UpdateUserRequest;
import com.eams.dto.response.UserResponse;
import com.eams.exception.EmailAlreadyExistsException;
import com.eams.exception.ResourceNotFoundException;
import com.eams.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(userRepository, passwordEncoder);
    }

    private User existingUser(UUID id) {
        return User.builder()
                .id(id)
                .fullName("Jane Doe")
                .email("jane.doe@example.com")
                .password("hashed-password")
                .role(Role.EMPLOYEE)
                .enabled(true)
                .build();
    }

    @Test
    void onboardUser_savesEncodedPasswordAndReturnsResponse() {
        RegisterRequest request = new RegisterRequest("New Hire", "new.hire@example.com", "plainPassword123", Role.EMPLOYEE);
        when(userRepository.existsByEmail(request.email())).thenReturn(false);
        when(passwordEncoder.encode(request.password())).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserResponse response = userService.onboardUser(request);

        ArgumentCaptor<User> savedUserCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(savedUserCaptor.capture());

        assertThat(savedUserCaptor.getValue().getPassword()).isEqualTo("encoded-password");
        assertThat(savedUserCaptor.getValue().isEnabled()).isTrue();
        assertThat(response.email()).isEqualTo(request.email());
        assertThat(response.role()).isEqualTo(Role.EMPLOYEE);
    }

    @Test
    void onboardUser_rejectsDuplicateEmail() {
        RegisterRequest request = new RegisterRequest("Dup", "dup@example.com", "plainPassword123", Role.EMPLOYEE);
        when(userRepository.existsByEmail(request.email())).thenReturn(true);

        assertThatThrownBy(() -> userService.onboardUser(request))
                .isInstanceOf(EmailAlreadyExistsException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void getUserById_throwsWhenNotFound() {
        UUID missingId = UUID.randomUUID();
        when(userRepository.findById(missingId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getUserById(missingId))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void updateUser_updatesFullNameOnly() {
        UUID id = UUID.randomUUID();
        User user = existingUser(id);
        when(userRepository.findById(id)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserResponse response = userService.updateUser(id, new UpdateUserRequest("Jane Updated"));

        assertThat(response.fullName()).isEqualTo("Jane Updated");
        assertThat(response.email()).isEqualTo("jane.doe@example.com"); // unchanged
    }

    @Test
    void setEnabled_flipsEnabledFlag() {
        UUID id = UUID.randomUUID();
        User user = existingUser(id);
        when(userRepository.findById(id)).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserResponse response = userService.setEnabled(id, false);

        assertThat(response.enabled()).isFalse();
    }

    @Test
    void getAllUsers_mapsEveryEntityToAResponse() {
        when(userRepository.findAll()).thenReturn(List.of(existingUser(UUID.randomUUID()), existingUser(UUID.randomUUID())));

        List<UserResponse> responses = userService.getAllUsers();

        assertThat(responses).hasSize(2);
    }
}
