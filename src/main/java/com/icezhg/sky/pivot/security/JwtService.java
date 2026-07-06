package com.icezhg.sky.pivot.security;

import com.icezhg.sky.pivot.config.properties.JwtProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey key;
    private final int miniappExpiryDays;
    private final int pcExpiryHours;

    public JwtService(JwtProperties jwtProperties) {
        String secret = jwtProperties.getSecret();
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(keyBytes, 0, padded, 0, keyBytes.length);
            keyBytes = padded;
        }
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.miniappExpiryDays = jwtProperties.getMiniappExpiryDays();
        this.pcExpiryHours = jwtProperties.getPcExpiryHours();
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
