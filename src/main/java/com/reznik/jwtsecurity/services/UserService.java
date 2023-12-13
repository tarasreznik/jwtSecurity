package com.reznik.jwtsecurity.services;

import com.reznik.jwtsecurity.repos.UserRepository;
import com.reznik.jwtsecurity.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User getLoggedInUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        return userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User with email: " + email + " not found"));
    }

    public User readUser() {
        Integer userId = getLoggedInUser().getId();
        return userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found for id:" + userId));
    }
}
