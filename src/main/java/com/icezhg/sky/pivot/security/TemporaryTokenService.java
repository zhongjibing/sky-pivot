package com.icezhg.sky.pivot.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class TemporaryTokenService {

    private final Cache<String, TokenData> tokenCache;

    public TemporaryTokenService(
        @Value("${app.security.token-expiry-seconds:60}") int expirySeconds
    ) {
        this.tokenCache = Caffeine.newBuilder()
            .expireAfterWrite(expirySeconds, TimeUnit.SECONDS)
            .maximumSize(10000)
            .build();
    }

    public String createToken(Long userId, TokenType type) {
        String token = UUID.randomUUID().toString();
        tokenCache.put(token, new TokenData(userId, type, Instant.now()));
        return token;
    }

    public TokenData consumeToken(String token, TokenType expectedType) {
        TokenData data = tokenCache.getIfPresent(token);
        if (data == null) {
            return null;
        }
        tokenCache.invalidate(token);
        if (data.type != expectedType) {
            return null;
        }
        return data;
    }

    public record TokenData(Long userId, TokenType type, Instant createdAt) {}

    public enum TokenType {
        BIOMETRIC,
        MASTER_PASSWORD
    }
}
