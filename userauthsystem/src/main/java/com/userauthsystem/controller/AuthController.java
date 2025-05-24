package com.userauthsystem.controller;

import com.userauthsystem.model.Role;
import com.userauthsystem.model.User;
import com.userauthsystem.service.UserService;
import com.userauthsystem.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
       // user.setRoles(Set.of(Role.USER)); // Default role for new users
        userService.registerUser(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        try {
        	
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User loggedInUser = userService.findByUsername(user.getUsername()).orElseThrow();
            loggedInUser = userService.incrementTokenVersion(loggedInUser); 
            String token = jwtUtil.generateToken(userDetails.getUsername(), loggedInUser.getRoles().stream()
                    .map(Enum::name).collect(Collectors.toSet()), loggedInUser.getTokenVersion());
            return ResponseEntity.ok(token);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String token) {
        String jwtToken = token.replace("Bearer ", "");
        String expiredToken = jwtUtil.expireToken(jwtToken); // Expire the token
        String username = jwtUtil.extractUsername(jwtToken);
        User user = userService.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        userService.incrementTokenVersion(user); // Increment the token version and save
        return ResponseEntity.ok("Logged out successfully");
    }
}