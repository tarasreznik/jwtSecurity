package com.reznik.jwtsecurity.controller;

import com.reznik.jwtsecurity.services.AuthenticationService;
import com.reznik.jwtsecurity.dto.AuthenticationRequest;
import com.reznik.jwtsecurity.dto.AuthenticationResponse;
import com.reznik.jwtsecurity.dto.AuthorizationRequest;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/authorize")
    public ResponseEntity<AuthenticationResponse> registerUser(@RequestBody AuthorizationRequest request){
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        service.refreshToken(request, response);
    }
}
