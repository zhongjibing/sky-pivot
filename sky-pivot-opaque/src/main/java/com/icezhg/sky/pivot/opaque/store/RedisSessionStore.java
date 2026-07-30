package com.icezhg.sky.pivot.opaque.store;

import com.codeheadsystems.hofmann.server.store.SessionData;
import com.codeheadsystems.hofmann.server.store.SessionStore;
import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

@Component
public class RedisSessionStore implements SessionStore {

    private static final Logger log = LoggerFactory.getLogger(RedisSessionStore.class);
    private static final Duration SESSION_TTL = Duration.ofMinutes(30);

    private final RedisService redisService;

    public RedisSessionStore(RedisService redisService) {
        this.redisService = redisService;
    }

    @Override
    public void store(String jti, SessionData sessionData) {
        String key = RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, "session", jti);
        String value = encodeValue(sessionData);
        redisService.set(key, value, SESSION_TTL);
        log.debug("Stored session: {}", jti);
    }

    @Override
    public Optional<SessionData> load(String jti) {
        String key = RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, "session", jti);
        return redisService.get(key, String.class)
                .map(this::decodeValue);
    }

    @Override
    public void revoke(String jti) {
        String key = RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, "session", jti);
        redisService.delete(key);
        String blacklistKey = RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, jti);
        redisService.set(blacklistKey, "revoked", Duration.ofHours(2));
        log.debug("Revoked session: {}", jti);
    }

    @Override
    public void revokeByCredentialIdentifier(String credentialIdentifierBase64) {
        String pattern = RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, "session", "*");
        try {
            Set<String> keys = redisService.keys(pattern);
            if (keys != null) {
                for (String key : keys) {
                    Optional<String> value = redisService.get(key, String.class);
                    if (value.isPresent() && value.get().startsWith(credentialIdentifierBase64 + ":")) {
                        redisService.delete(key);
                    }
                }
            }
            log.debug("Revoked all sessions for credential: {}", credentialIdentifierBase64);
        } catch (Exception e) {
            log.warn("Failed to revoke sessions by credential identifier: {}", credentialIdentifierBase64, e);
        }
    }

    private String encodeValue(SessionData sessionData) {
        return sessionData.credentialIdentifier() + ":" +
                sessionData.sessionKey() + ":" +
                sessionData.issuedAt().toEpochMilli() + ":" +
                sessionData.expiresAt().toEpochMilli();
    }

    private SessionData decodeValue(String value) {
        String[] parts = value.split(":", 4);
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid session data format");
        }
        return new SessionData(
                parts[0],
                parts[1],
                Instant.ofEpochMilli(Long.parseLong(parts[2])),
                Instant.ofEpochMilli(Long.parseLong(parts[3]))
        );
    }
}
