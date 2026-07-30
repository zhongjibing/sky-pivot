package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class RateLimitService {

    private static final Logger log = LoggerFactory.getLogger(RateLimitService.class);
    private static final int MAX_LOGIN_START_PER_MINUTE = 10;

    private final RedisService redisService;

    public RateLimitService(RedisService redisService) {
        this.redisService = redisService;
    }

    public boolean isLoginStartAllowed(String ip) {
        String key = RedisKeyPrefix.key(RedisKeyPrefix.OPRF_LIMIT, ip);
        Long count = redisService.increment(key);
        if (count != null && count == 1) {
            redisService.expire(key, RedisKeyPrefix.TTL_OPRF_LIMIT);
        }
        boolean allowed = count != null && count <= MAX_LOGIN_START_PER_MINUTE;
        if (!allowed) {
            log.warn("Rate limit exceeded for IP: {}, count: {}", ip, count);
        }
        return allowed;
    }

    public long getRemainingAttempts(String ip) {
        String key = RedisKeyPrefix.key(RedisKeyPrefix.OPRF_LIMIT, ip);
        return redisService.get(key, Long.class)
                .map(count -> Math.max(0, MAX_LOGIN_START_PER_MINUTE - count))
                .orElse((long) MAX_LOGIN_START_PER_MINUTE);
    }
}
