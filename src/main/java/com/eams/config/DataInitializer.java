package com.eams.config;

import com.eams.domain.Role;
import com.eams.domain.User;
import com.eams.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Onboarding new users is ADMIN-only (see UserController), which means the
 * very first ADMIN can't be created through the API. This runs once at
 * startup and creates one from config if it doesn't already exist -
 * change the password immediately after first login in any real deployment.
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final BootstrapAdminProperties bootstrapAdminProperties;

    public DataInitializer(UserRepository userRepository,
                            PasswordEncoder passwordEncoder,
                            BootstrapAdminProperties bootstrapAdminProperties) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.bootstrapAdminProperties = bootstrapAdminProperties;
    }

    @Override
    public void run(String... args) {
        if (userRepository.existsByEmail(bootstrapAdminProperties.email())) {
            return;
        }

        User admin = User.builder()
                .fullName(bootstrapAdminProperties.fullName())
                .email(bootstrapAdminProperties.email())
                .password(passwordEncoder.encode(bootstrapAdminProperties.password()))
                .role(Role.ADMIN)
                .enabled(true)
                .build();

        userRepository.save(admin);
        log.info("Bootstrap ADMIN account created: {}", bootstrapAdminProperties.email());
    }
}
