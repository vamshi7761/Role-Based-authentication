package com.userauthsystem.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.userauthsystem.service.UserService;
import com.userauthsystem.util.JwtUtil;

@Configuration
public class FilterConfig {
    
    @Bean
    public JwtTokenFilter jwtTokenFilter(JwtUtil jwtUtil, UserService userService) {
        return new JwtTokenFilter(jwtUtil, userService);
    }
}
