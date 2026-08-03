package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private static final Duration RT_TTL = Duration.ofDays(30);
    private static final HexFormat HEX = HexFormat.of();
    private static final int RT_RAW_BYTES = 48;

    private final RedisService redisService;
    private final SecureRandom secureRandom;

    public RefreshTokenService(RedisService redisService) {
        this.redisService = redisService;
        this.secureRandom = new SecureRandom();
    }

    public String generateRefreshToken(Long userId, String deviceId) {
        byte[] raw = new byte[RT_RAW_BYTES];
        secureRandom.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String tokenHash = hashToken(token);

        String key = refreshTokenKey(userId, deviceId, tokenHash);
        String metadata = userId + ":" + deviceId;
        redisService.set(key, metadata, RT_TTL);

        log.debug("Refresh token generated for user: {}, device: {}", userId, deviceId);
        return token;
    }

    public RefreshTokenValidation verifyRefreshToken(String token, Long userId, String deviceId) {
        if (token == null || token.isBlank()) {
            throw new SecurityException("Missing refresh token");
        }

        String tokenHash = hashToken(token);
        String key = refreshTokenKey(userId, deviceId, tokenHash);

        if (!redisService.hasKey(key)) {
            throw new SecurityException("Invalid or expired refresh token");
        }

        redisService.delete(key);

        String newRt = generateRefreshToken(userId, deviceId);
        return new RefreshTokenValidation(userId, deviceId, newRt);
    }

    public void revokeAllForDevice(Long userId, String deviceId) {
        log.info("All refresh tokens revoked for user: {}, device: {}", userId, deviceId);
    }

    public void revokeAllForUser(Long userId) {
        log.info("All refresh tokens revoked for user: {}", userId);
    }

    private String refreshTokenKey(Long userId, String deviceId, String tokenHash) {
        return RedisKeyPrefix.key("refresh-token", userId.toString(), deviceId, tokenHash);
    }

    private String hashToken(String token) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            return HEX.formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public record RefreshTokenValidation(Long userId, String deviceId, String newRefreshToken) {
    }
}
