package com.eams.security;

import com.eams.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Only used at LOGIN time, to look the user up by email and let
 * DaoAuthenticationProvider check their password. Every request AFTER
 * login is authenticated purely from the JWT (see SecurityConfig's
 * JwtDecoder/JwtAuthenticationConverter) - we never hit the DB just to
 * validate a bearer token.
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("No user found with email: " + email));
    }
}
