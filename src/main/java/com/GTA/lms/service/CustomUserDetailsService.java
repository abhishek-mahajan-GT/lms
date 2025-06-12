package com.GTA.lms.service;

import com.GTA.lms.entity.User;
import com.GTA.lms.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.Collections;
import org.slf4j.Logger; 
import org.slf4j.LoggerFactory; 

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class); 

    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        logger.info("Attempting to load user by username or email: {}", usernameOrEmail); 

        User user = userRepository.findByUsername(usernameOrEmail)
                .orElseGet(() -> {
                    logger.info("User not found by username. Trying to find by email: {}", usernameOrEmail); 
                    return userRepository.findByEmail(usernameOrEmail)
                        .orElseThrow(() -> {
                            logger.error("User not found in database for username or email: {}", usernameOrEmail);
                            return new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail);
                        });
                });

        logger.info("User found: Email={}, Username={}, Password (encoded, first 10 chars)={}",
                    user.getEmail(), user.getUsername(), user.getPassword().substring(0, Math.min(user.getPassword().length(), 10))); // Log found user info

        return new org.springframework.security.core.userdetails.User(user.getEmail(),
                user.getPassword(),
                Collections.emptyList());
    }
}
