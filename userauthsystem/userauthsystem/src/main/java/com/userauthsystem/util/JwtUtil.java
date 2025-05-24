package com.userauthsystem.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.userauthsystem.model.User;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

@Component
public class JwtUtil {

    private final Key key;
    
    @Value("${jwt.secret}")
    private String secretKey;

    public JwtUtil(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        this.key = new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    public String generateToken(String username, Set<String> roles, long tokenVersion) {
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .claim("tokenVersion", tokenVersion)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 30)) // Adjust expiration time as needed
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String expireToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis())) // Immediate expiration
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return getAllClaimsFromToken(token).getSubject();
    }

    public long extractTokenVersion(String token) {
        return getAllClaimsFromToken(token).get("tokenVersion", Long.class);
    }

    public Set<String> extractRoles(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return claims.get("roles", Set.class); // Ensure the type matches the type used while creating
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public boolean isTokenValid(String token, User user) {
        return validateToken(token, user) && extractTokenVersion(token) == user.getTokenVersion();
    }

    private boolean isTokenExpired(String token) {
        return getAllClaimsFromToken(token).getExpiration().before(new Date());
    }
}