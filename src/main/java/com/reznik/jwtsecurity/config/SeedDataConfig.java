package com.reznik.jwtsecurity.config;

import com.reznik.jwtsecurity.repos.UserRepository;
import com.reznik.jwtsecurity.entity.Role;
import com.reznik.jwtsecurity.entity.User;
import com.reznik.jwtsecurity.services.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class SeedDataConfig implements CommandLineRunner {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {

        if (userRepository.count() == 0) {

            User admin = User
                    .builder()
                    .firstName("admin")
                    .lastName("admin")
                    .email("admin@admin.com")
                    .password(passwordEncoder.encode("password"))
                    .role(Role.ADMIN)
                    .build();

            userRepository.save(admin);
            log.debug("created ADMIN user - {}", admin);
        }
    }

}
