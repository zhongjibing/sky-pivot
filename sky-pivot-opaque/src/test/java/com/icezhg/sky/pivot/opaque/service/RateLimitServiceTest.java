package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RateLimitService Tests")
class RateLimitServiceTest {

    private RateLimitService rateLimitService;
    private InMemoryRedisService redisService;

    @BeforeEach
    void setUp() {
        redisService = new InMemoryRedisService();
        rateLimitService = new RateLimitService(redisService);
    }

    @Test
    @DisplayName("AC-4: Should allow up to 10 login-start requests in 1 minute")
    void shouldAllowUpTo10Requests() {
        String ip = "192.168.1.1";
        for (int i = 0; i < 10; i++) {
            assertTrue(rateLimitService.isLoginStartAllowed(ip),
                    "Request " + (i + 1) + " should be allowed");
        }
        assertEquals(0, rateLimitService.getRemainingAttempts(ip));
    }

    @Test
    @DisplayName("AC-4: 11th login-start request should return false (rate limit exceeded)")
    void shouldReject11thRequest() {
        String ip = "192.168.1.2";
        for (int i = 0; i < 10; i++) {
            rateLimitService.isLoginStartAllowed(ip);
        }
        assertFalse(rateLimitService.isLoginStartAllowed(ip),
                "11th request should be rate limited");
        assertEquals(0, rateLimitService.getRemainingAttempts(ip));
    }

    @Test
    @DisplayName("Should track rate limits per IP independently")
    void shouldTrackPerIp() {
        String ip1 = "10.0.0.1";
        String ip2 = "10.0.0.2";

        for (int i = 0; i < 5; i++) {
            rateLimitService.isLoginStartAllowed(ip1);
        }
        assertEquals(10, rateLimitService.getRemainingAttempts(ip2),
                "IP2 should have all attempts remaining since it has zero requests");
        assertEquals(5, rateLimitService.getRemainingAttempts(ip1));
    }

    @Test
    @DisplayName("Should track separate counters for each IP")
    void shouldTrackSeparateCountersPerIp() {
        String ip1 = "10.0.0.1";
        String ip2 = "10.0.0.2";

        rateLimitService.isLoginStartAllowed(ip1);
        rateLimitService.isLoginStartAllowed(ip2);
        rateLimitService.isLoginStartAllowed(ip2);

        assertEquals(9, rateLimitService.getRemainingAttempts(ip1));
        assertEquals(8, rateLimitService.getRemainingAttempts(ip2));
    }

    @Test
    @DisplayName("Should return max attempts when no requests have been made")
    void shouldReturnMaxAttemptsWhenNoRequests() {
        assertEquals(10, rateLimitService.getRemainingAttempts("10.0.0.3"));
    }

    @Test
    @DisplayName("Should not go below zero remaining attempts")
    void shouldNotGoBelowZeroRemaining() {
        String ip = "192.168.1.3";
        for (int i = 0; i < 20; i++) {
            rateLimitService.isLoginStartAllowed(ip);
        }
        assertEquals(0, rateLimitService.getRemainingAttempts(ip));
    }

    private static class InMemoryRedisService extends RedisService {
        private final Map<String, Object> store = new ConcurrentHashMap<>();

        InMemoryRedisService() {
            super(null);
        }

        @Override
        public Long increment(String key) {
            Object current = store.get(key);
            long newVal = current instanceof Long ? (Long) current + 1 : 1;
            store.put(key, newVal);
            return newVal;
        }

        @Override
        public Long increment(String key, long delta) {
            Object current = store.get(key);
            long newVal = current instanceof Long ? (Long) current + delta : delta;
            store.put(key, newVal);
            return newVal;
        }

        @Override
        @SuppressWarnings("unchecked")
        public <T> Optional<T> get(String key, Class<T> type) {
            Object value = store.get(key);
            if (value == null) return Optional.empty();
            return Optional.of((T) value);
        }

        @Override
        public Boolean expire(String key, Duration timeout) {
            return true;
        }
    }
}
