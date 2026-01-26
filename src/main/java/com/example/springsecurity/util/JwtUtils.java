package com.example.springsecurity.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Component
public class JwtUtils {

    private SecretKey secretKey;

    // Manage the expiration duration
    public static final long EXPIRATION_TIME = 60 * 24 * 60 * 1000; // 86400000 milliseconds = 24 hours

    // generate a message authentication code (MAC) using the secret key in combination with the SHA-256 hash function.
    public JwtUtils() {
        // Manage the secret
        String secretString = "f2a8c3d9e5b7a1c4d2e8f0a3b6c9d5e7f1a4b8c2d6e0f3a7b9c1d5e8f2a4b6c8";
        byte[] keyBytes = Base64.getDecoder().decode(secretString.getBytes(StandardCharsets.UTF_8));
        this.secretKey = new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    // takes in the user's details to generate the JWT token with an expiration duration of 24 hours
    public String generateToken(UserDetails userDetails){
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .claim("roles", userDetails.getAuthorities())
                .signWith(secretKey)
                .compact();
    }

    // takes in the claims (aka payload, e.g. expirationTime) and the user's details to generate a refresh token
    public String generateRefreshToken(HashMap<String, Object> claims, UserDetails userDetails){
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .claim("roles", userDetails.getAuthorities())
                .signWith(secretKey)
                .compact();
    }

    // returns the duration of expiry
    public Long extractExpirationTime(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)          // Ensure the key matches the one used for signing
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()                // Returns a java.util.Date
                .getTime();                     // Converts Date to Long (milliseconds)
    }

    // check if the token used is valid
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // returns the username (email) using the passed-in token
    // the token is the payload containing user information (e.g. email, expirationTime)
    public String extractUsername(String token){
        return extractClaims(token, Claims::getSubject);
    }

    // this generic method, represented by <T> returns a generic type as well T
    // returns the claims (payload) from a JWT (JSON Web Token)
    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction){
        return claimsTFunction.apply(Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload());
    }

    // returns whether the token is expired by comparing the token's expiration against the current date
    public boolean isTokenExpired(String token){
        return extractClaims(token, Claims::getExpiration).before(new Date());
    }

}