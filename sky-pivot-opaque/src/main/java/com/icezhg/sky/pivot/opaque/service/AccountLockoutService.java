package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class AccountLockoutService {

    private static final Logger log = LoggerFactory.getLogger(AccountLockoutService.class);

    private static final int CAPTCHA_THRESHOLD = 5;
    private static final int LOCKOUT_THRESHOLD = 10;

    private static final String CONSECUTIVE_LOCKOUTS_KEY = "login:consecutive-lockouts";

    private final RedisService redisService;
    private final NotificationService notificationService;

    public AccountLockoutService(RedisService redisService, NotificationService notificationService) {
        this.redisService = redisService;
        this.notificationService = notificationService;
    }

    public void checkAccountLocked(Long userId) {
        if (isLocked(userId)) {
            throw new SecurityException("Account is locked due to too many failed login attempts");
        }
    }

    public boolean isCaptchaRequired(Long userId) {
        return getFailedAttempts(userId) >= CAPTCHA_THRESHOLD;
    }

    public int getFailedAttempts(Long userId) {
        String attemptsKey = RedisKeyPrefix.key(RedisKeyPrefix.LOGIN_ATTEMPTS, userId.toString());
        return redisService.get(attemptsKey, String.class)
                .map(Integer::parseInt)
                .orElse(0);
    }

    public int getRemainingAttempts(Long userId) {
        if (isLocked(userId)) return 0;
        int current = getFailedAttempts(userId);
        return Math.max(0, LOCKOUT_THRESHOLD - current);
    }

    public void recordFailedAttempt(Long userId) {
        String attemptsKey = RedisKeyPrefix.key(RedisKeyPrefix.LOGIN_ATTEMPTS, userId.toString());

        Long newCount = redisService.increment(attemptsKey);
        redisService.expire(attemptsKey, RedisKeyPrefix.TTL_LOGIN_ATTEMPTS);

        log.warn("Failed login attempt {} for userId={}", newCount, userId);

        if (newCount != null && newCount >= LOCKOUT_THRESHOLD) {
            lockAccount(userId);
        }
    }

    public void resetAttempts(Long userId) {
        String attemptsKey = RedisKeyPrefix.key(RedisKeyPrefix.LOGIN_ATTEMPTS, userId.toString());
        redisService.delete(attemptsKey);

        String consecutiveKey = RedisKeyPrefix.key(CONSECUTIVE_LOCKOUTS_KEY, userId.toString());
        redisService.delete(consecutiveKey);

        log.debug("Login attempts reset for userId={}", userId);
    }

    public boolean isLocked(Long userId) {
        String lockedKey = RedisKeyPrefix.key(RedisKeyPrefix.LOGIN_LOCKED, userId.toString());
        return redisService.hasKey(lockedKey);
    }

    private void lockAccount(Long userId) {
        String lockedKey = RedisKeyPrefix.key(RedisKeyPrefix.LOGIN_LOCKED, userId.toString());
        String consecutiveKey = RedisKeyPrefix.key(CONSECUTIVE_LOCKOUTS_KEY, userId.toString());

        Long consecutive = redisService.increment(consecutiveKey);
        redisService.expire(consecutiveKey, Duration.ofHours(2));

        int consecutiveInt = consecutive != null ? consecutive.intValue() : 1;
        Duration lockDuration = RedisKeyPrefix.lockoutDuration(consecutiveInt - 1);

        redisService.set(lockedKey, String.valueOf(lockDuration.toMinutes()), lockDuration);

        log.warn("Account locked for userId={}, duration={}, consecutive lockouts={}",
                userId, lockDuration, consecutiveInt);

        notificationService.sendAccountLockedNotification(userId, lockDuration.toMinutes());
    }
}
