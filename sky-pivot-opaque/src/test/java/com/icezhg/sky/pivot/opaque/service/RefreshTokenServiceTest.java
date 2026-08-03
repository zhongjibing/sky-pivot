package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RefreshTokenService Tests")
class RefreshTokenServiceTest {

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(new FakeRedisService());
    }

    @Test
    @DisplayName("Generate refresh token should return non-null string")
    void shouldGenerateRefreshToken() {
        String rt = refreshTokenService.generateRefreshToken(1L, "device-001");
        assertNotNull(rt);
        assertFalse(rt.isBlank());
        assertTrue(rt.length() >= 32);
    }

    @Test
    @DisplayName("Verify valid refresh token should succeed and return new token")
    void shouldVerifyAndRotateRefreshToken() {
        String rt = refreshTokenService.generateRefreshToken(1L, "device-001");
        assertNotNull(rt);

        var result = refreshTokenService.verifyRefreshToken(rt, 1L, "device-001");
        assertNotNull(result);
        assertEquals(1L, result.userId());
        assertEquals("device-001", result.deviceId());
        assertNotNull(result.newRefreshToken());
        assertNotEquals(rt, result.newRefreshToken());
    }

    @Test
    @DisplayName("Same refresh token used twice should fail (rotation)")
    void shouldRejectReusedRefreshToken() {
        String rt = refreshTokenService.generateRefreshToken(1L, "device-001");

        var result1 = refreshTokenService.verifyRefreshToken(rt, 1L, "device-001");
        assertNotNull(result1);

        assertThrows(SecurityException.class, () ->
                refreshTokenService.verifyRefreshToken(rt, 1L, "device-001"));
    }

    @Test
    @DisplayName("Null or blank refresh token should fail")
    void shouldRejectNullOrBlankRt() {
        assertThrows(SecurityException.class, () ->
                refreshTokenService.verifyRefreshToken(null, 1L, "device-001"));
        assertThrows(SecurityException.class, () ->
                refreshTokenService.verifyRefreshToken("", 1L, "device-001"));
    }

    @Test
    @DisplayName("Wrong userId should fail verification")
    void shouldRejectWrongUserId() {
        String rt = refreshTokenService.generateRefreshToken(1L, "device-001");
        assertThrows(SecurityException.class, () ->
                refreshTokenService.verifyRefreshToken(rt, 999L, "device-001"));
    }

    @Test
    @DisplayName("Wrong deviceId should fail verification")
    void shouldRejectWrongDeviceId() {
        String rt = refreshTokenService.generateRefreshToken(1L, "device-001");
        assertThrows(SecurityException.class, () ->
                refreshTokenService.verifyRefreshToken(rt, 1L, "wrong-device"));
    }

    @Test
    @DisplayName("Multiple refresh tokens for same device should be independent")
    void shouldHaveIndependentRefreshTokens() {
        String rt1 = refreshTokenService.generateRefreshToken(1L, "device-001");
        String rt2 = refreshTokenService.generateRefreshToken(1L, "device-001");

        assertNotEquals(rt1, rt2);

        refreshTokenService.verifyRefreshToken(rt1, 1L, "device-001");

        var result2 = refreshTokenService.verifyRefreshToken(rt2, 1L, "device-001");
        assertNotNull(result2);
    }

    @Test
    @DisplayName("Different devices should have independent tokens")
    void shouldHaveIndependentTokensForDifferentDevices() {
        String rt1 = refreshTokenService.generateRefreshToken(1L, "device-001");
        String rt2 = refreshTokenService.generateRefreshToken(1L, "device-002");

        var result1 = refreshTokenService.verifyRefreshToken(rt1, 1L, "device-001");
        assertNotNull(result1);

        var result2 = refreshTokenService.verifyRefreshToken(rt2, 1L, "device-002");
        assertNotNull(result2);

        assertThrows(SecurityException.class, () ->
                refreshTokenService.verifyRefreshToken(rt1, 1L, "device-002"));
    }

    static class FakeRedisService extends RedisService {
        private final java.util.Map<String, Object> store = new java.util.concurrent.ConcurrentHashMap<>();

        FakeRedisService() {
            super(null);
        }

        @Override
        public void set(String key, Object value, Duration timeout) {
            store.put(key, value);
        }

        @Override
        public Boolean hasKey(String key) {
            return store.containsKey(key);
        }

        @Override
        public Boolean delete(String key) {
            return store.remove(key) != null;
        }
    }
}
