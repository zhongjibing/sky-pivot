package com.icezhg.sky.pivot.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey key;

    @Value("${app.jwt.miniapp-expiry-days:7}")
    private int miniappExpiryDays;

    @Value("${app.jwt.pc-expiry-hours:2}")
    private int pcExpiryHours;

    public JwtService(@Value("${app.jwt.secret}") String secret) {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(keyBytes, 0, padded, 0, keyBytes.length);
            keyBytes = padded;
        }
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String issueMiniAppToken(Long userId) {
        return issueToken(userId, Duration.ofDays(miniappExpiryDays));
    }

    public String issuePcToken(Long userId) {
        return issueToken(userId, Duration.ofHours(pcExpiryHours));
    }

    public String issueToken(Long userId, Duration expiry) {
        Instant now = Instant.now();
        return Jwts.builder()
            .subject(userId.toString())
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plus(expiry)))
            .signWith(key)
            .compact();
    }

    public Long validateToken(String token) {
        try {
            Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
            return Long.parseLong(claims.getSubject());
        } catch (JwtException | IllegalArgumentException e) {
            throw new TokenValidationException("Invalid or expired token", e);
        }
    }

    public static class TokenValidationException extends RuntimeException {
        public TokenValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
