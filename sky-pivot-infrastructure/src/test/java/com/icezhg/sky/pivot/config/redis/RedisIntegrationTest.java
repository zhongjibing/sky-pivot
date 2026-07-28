package com.icezhg.sky.pivot.config.redis;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Redis Integration Tests")
@Tag("integration")
class RedisIntegrationTest {

    private static RedisTemplate<String, Object> redisTemplate;
    private static RedisService redisService;
    private static LettuceConnectionFactory connectionFactory;

    @BeforeAll
    static void setUp() {
        RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
        config.setHostName("localhost");
        config.setPort(6379);

        connectionFactory = new LettuceConnectionFactory(config);
        connectionFactory.afterPropertiesSet();

        redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(connectionFactory);

        RedisSerializer<String> stringSerializer = RedisSerializer.string();
        redisTemplate.setKeySerializer(stringSerializer);
        redisTemplate.setHashKeySerializer(stringSerializer);

        GenericJackson2JsonRedisSerializer jsonSerializer = new GenericJackson2JsonRedisSerializer();
        redisTemplate.setValueSerializer(jsonSerializer);
        redisTemplate.setHashValueSerializer(jsonSerializer);

        redisTemplate.afterPropertiesSet();

        try {
            redisTemplate.opsForValue().get("sky-pivot:health:ping");
        } catch (RedisConnectionFailureException e) {
            Assumptions.abort("Redis is not available at localhost:6379 — skipping integration tests");
        }

        redisService = new RedisService(redisTemplate);
    }

    @AfterEach
    void tearDown() {
        Set<String> keys = redisTemplate.keys(RedisKeyPrefix.NAMESPACE + ":*");
        if (keys != null && !keys.isEmpty()) {
            redisTemplate.delete(keys);
        }
    }

    @Test
    @DisplayName("Should connect to Redis and ping successfully")
    void shouldConnectToRedis() {
        assertTrue(redisService.isHealthy());
    }

    @Test
    @DisplayName("Should set and get a value")
    void shouldSetAndGetValue() {
        String key = RedisKeyPrefix.key("test", "simple");
        redisService.set(key, "hello-world");

        Optional<String> result = redisService.get(key, String.class);
        assertTrue(result.isPresent());
        assertEquals("hello-world", result.get());
    }

    @Test
    @DisplayName("Should set value with TTL and verify expiry")
    void shouldSetValueWithTTL() {
        String key = RedisKeyPrefix.key("test", "ttl");
        redisService.set(key, "expires-soon", Duration.ofSeconds(10));

        Long ttl = redisService.getExpire(key, TimeUnit.SECONDS);
        assertTrue(ttl > 0 && ttl <= 10);
    }

    @Test
    @DisplayName("Should delete a key")
    void shouldDeleteKey() {
        String key = RedisKeyPrefix.key("test", "delete-me");
        redisService.set(key, "temp");

        Boolean deleted = redisService.delete(key);
        assertTrue(deleted);

        Optional<Object> gone = redisService.get(key);
        assertFalse(gone.isPresent());
    }

    @Test
    @DisplayName("Should check key existence")
    void shouldCheckKeyExistence() {
        String key = RedisKeyPrefix.key("test", "exists");
        assertFalse(redisService.hasKey(key));

        redisService.set(key, "present");
        assertTrue(redisService.hasKey(key));
    }

    @Test
    @DisplayName("Should increment counter")
    void shouldIncrementCounter() {
        String key = RedisKeyPrefix.key("test", "counter");

        Long v1 = redisService.increment(key);
        assertEquals(1L, v1);

        Long v2 = redisService.increment(key, 5);
        assertEquals(6L, v2);
    }

    @Test
    @DisplayName("Should store and read integer value")
    void shouldStoreIntegerValue() {
        String key = RedisKeyPrefix.key("test", "intval");

        redisService.set(key, 42);
        Optional<Integer> result = redisService.get(key, Integer.class);
        assertTrue(result.isPresent());
        assertEquals(42, result.get());
    }

    @Test
    @DisplayName("Should set add and check membership")
    void shouldSetAddAndCheckMembership() {
        String key = RedisKeyPrefix.key("test", "myset");
        redisService.setAdd(key, "a", "b", "c");

        assertTrue(redisService.setIsMember(key, "b"));
        assertFalse(redisService.setIsMember(key, "d"));

        Set<Object> members = redisService.setMembers(key);
        assertEquals(3, members.size());
    }

    @Test
    @DisplayName("Should hash put and get")
    void shouldHashPutAndGet() {
        String key = RedisKeyPrefix.key("test", "hash");
        redisService.hashPut(key, "field1", "value1");
        redisService.hashPut(key, "field2", 100);

        assertTrue(redisService.hashHasKey(key, "field1"));

        Optional<String> strVal = redisService.hashGet(key, "field1", String.class);
        assertTrue(strVal.isPresent());
        assertEquals("value1", strVal.get());

        Optional<Integer> intVal = redisService.hashGet(key, "field2", Integer.class);
        assertTrue(intVal.isPresent());
        assertEquals(100, intVal.get());
    }

    @Test
    @DisplayName("Should scan keys matching pattern")
    void shouldScanKeys() {
        String k1 = RedisKeyPrefix.key("test", "scan", "alpha");
        String k2 = RedisKeyPrefix.key("test", "scan", "beta");
        String k3 = RedisKeyPrefix.key("test", "noise");

        redisService.set(k1, "a");
        redisService.set(k2, "b");
        redisService.set(k3, "c");

        Set<String> keys = redisService.keys(RedisKeyPrefix.key("test", "scan", "*"));
        assertNotNull(keys);
        assertTrue(keys.containsAll(Set.of(k1, k2)));
    }

    @Test
    @DisplayName("Should follow key naming convention with namespace prefix")
    void shouldFollowKeyNamingConvention() {
        String key = RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, "jti-abc-123");
        assertTrue(key.startsWith(RedisKeyPrefix.NAMESPACE + ":"));
        assertTrue(key.startsWith(RedisKeyPrefix.NAMESPACE + ":" + RedisKeyPrefix.JWT_BLACKLIST));

        redisService.set(key, "revoked", RedisKeyPrefix.TTL_RECOVERY_CHALLENGE);
        assertTrue(redisService.hasKey(key));
    }

    @Test
    @DisplayName("Should construct all required key patterns")
    void shouldConstructAllKeyPatterns() {
        assertEquals("sky-pivot:login:attempts:user123:192.168.1.1",
                RedisKeyPrefix.key(RedisKeyPrefix.LOGIN_ATTEMPTS, "user123", "192.168.1.1"));
        assertEquals("sky-pivot:login:locked:user123",
                RedisKeyPrefix.key(RedisKeyPrefix.LOGIN_LOCKED, "user123"));
        assertEquals("sky-pivot:oprf:limit:192.168.1.1",
                RedisKeyPrefix.key(RedisKeyPrefix.OPRF_LIMIT, "192.168.1.1"));
        assertEquals("sky-pivot:jwt:blacklist:jti-xyz-789",
                RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, "jti-xyz-789"));
        assertEquals("sky-pivot:recovery:challenge:user123",
                RedisKeyPrefix.key(RedisKeyPrefix.RECOVERY_CHALLENGE, "user123"));
        assertEquals("sky-pivot:recovery:used:authCode456",
                RedisKeyPrefix.key(RedisKeyPrefix.RECOVERY_USED, "authCode456"));
    }

    @Test
    @DisplayName("Should provide escalating lockout durations")
    void shouldProvideEscalatingLockoutDurations() {
        assertEquals(Duration.ofMinutes(15), RedisKeyPrefix.lockoutDuration(0));
        assertEquals(Duration.ofMinutes(15), RedisKeyPrefix.lockoutDuration(1));
        assertEquals(Duration.ofMinutes(30), RedisKeyPrefix.lockoutDuration(2));
        assertEquals(Duration.ofMinutes(60), RedisKeyPrefix.lockoutDuration(3));
        assertEquals(Duration.ofMinutes(120), RedisKeyPrefix.lockoutDuration(4));
        assertEquals(Duration.ofMinutes(120), RedisKeyPrefix.lockoutDuration(10));
    }

    @Test
    @DisplayName("Should handle 1000 concurrent operations without error")
    void shouldHandleConcurrentOperations() throws Exception {
        String baseKey = RedisKeyPrefix.key("test", "concurrent");
        int concurrency = 1000;
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        CountDownLatch latch = new CountDownLatch(concurrency);

        try {
            for (int i = 0; i < concurrency; i++) {
                final int idx = i;
                executor.submit(() -> {
                    try {
                        String key = baseKey + ":" + idx;
                        redisService.set(key, "value-" + idx, Duration.ofMinutes(5));
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(30, TimeUnit.SECONDS));

            for (int i = 0; i < concurrency; i++) {
                String key = baseKey + ":" + i;
                assertTrue(redisService.hasKey(key), "Key " + key + " should exist");
            }
        } finally {
            executor.shutdown();
            executor.awaitTermination(10, TimeUnit.SECONDS);
        }
    }

    @Test
    @DisplayName("Should handle TTL accurately")
    void shouldHandleTTLAccurately() {
        String key = RedisKeyPrefix.key("test", "ttl-accuracy");

        redisService.set(key, "data", RedisKeyPrefix.TTL_LOGIN_ATTEMPTS);
        Long ttl = redisService.getExpire(key, TimeUnit.MINUTES);
        assertTrue(ttl > 0 && ttl <= 60); // 1 hour = 60 minutes

        redisService.expire(key, Duration.ofMinutes(5));
        ttl = redisService.getExpire(key, TimeUnit.MINUTES);
        assertTrue(ttl > 0 && ttl <= 5);
    }

    @Test
    @DisplayName("Should get raw RedisTemplate")
    void shouldGetRawRedisTemplate() {
        RedisTemplate<String, Object> raw = redisService.raw();
        assertNotNull(raw);

        String key = RedisKeyPrefix.key("test", "raw");
        raw.opsForValue().set(key, "direct-access");
        assertEquals("direct-access", raw.opsForValue().get(key));
    }
}
