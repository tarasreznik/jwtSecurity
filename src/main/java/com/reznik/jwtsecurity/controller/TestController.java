package com.reznik.jwtsecurity.controller;

import com.reznik.jwtsecurity.services.UserService;
import com.reznik.jwtsecurity.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo-controller")
@RequiredArgsConstructor
public class TestController {

    private final UserService userService;

    @GetMapping
    public ResponseEntity<String> sayHello(){
        return ResponseEntity.ok("Hello from secured app");
    }

//    @GetMapping("/protected")
//    @Secured("ADMIN") // Role-based authorization
//    public String protectedResource() {
//        return "This is a protected resource.";
//    }

    @GetMapping("/me")
    public ResponseEntity<User> readUser() {
        return new ResponseEntity<>(userService.readUser(), HttpStatus.OK);
    }

}
