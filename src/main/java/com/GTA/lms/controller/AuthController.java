package com.GTA.lms.controller;

import com.GTA.lms.entity.User;
import com.GTA.lms.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private AuthService authService;

    public AuthController(AuthService authService)
    {
        this.authService = authService;
    }

    @PostMapping(value = {"/register"})
    public ResponseEntity<String> register(@RequestBody User user)
    {
        String response = authService.register(user);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

   

    @GetMapping("/logout-success")
    public ResponseEntity<String> logoutSuccess()
    {
        return ResponseEntity.ok("Logged out successfully!");
    }

    @GetMapping("/check-auth")
    public ResponseEntity<String> checkAuth()
    {
        if (SecurityContextHolder.getContext().getAuthentication() != null &&
            SecurityContextHolder.getContext().getAuthentication().isAuthenticated() &&
            !"anonymousUser".equals(SecurityContextHolder.getContext().getAuthentication().getPrincipal())) {
            return ResponseEntity.ok("authenticated.");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not authenticated.");
        }
    }
}
