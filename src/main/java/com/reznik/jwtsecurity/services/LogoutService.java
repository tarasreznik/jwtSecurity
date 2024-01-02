package com.reznik.jwtsecurity.services;

import com.reznik.jwtsecurity.entity.User;
import com.reznik.jwtsecurity.repos.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {
    private final UserRepository userRepository;
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        jwt = authHeader.substring(7);

        User user = userRepository.findByAccessToken(jwt).get();
        var storedToken = user.getAccessToken();

        if(storedToken != null){
            SecurityContextHolder.getContext().setAuthentication(null);
            user.setAccessToken(null);
            user.setRefreshToken(null);
            userRepository.save(user);

        }
    }
}
