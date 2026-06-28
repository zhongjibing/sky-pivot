package com.icezhg.sky.pivot.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class BiometricLockoutService {

    private final Cache<Long, Integer> failureCount;
    private final int maxFailures;

    public BiometricLockoutService(
        @Value("${app.security.biometric-max-failures:3}") int maxFailures,
        @Value("${app.security.biometric-lockout-minutes:5}") int lockoutMinutes
    ) {
        this.maxFailures = maxFailures;
        this.failureCount = Caffeine.newBuilder()
            .expireAfterWrite(lockoutMinutes, TimeUnit.MINUTES)
            .maximumSize(10000)
            .build();
    }

    public void recordFailure(Long userId) {
        int count = failureCount.get(userId, k -> 0);
        failureCount.put(userId, count + 1);
    }

    public boolean isLockedOut(Long userId) {
        Integer count = failureCount.getIfPresent(userId);
        return count != null && count >= maxFailures;
    }

    public void resetFailures(Long userId) {
        failureCount.invalidate(userId);
    }

    public int getRemainingAttempts(Long userId) {
        Integer count = failureCount.getIfPresent(userId);
        if (count == null) return maxFailures;
        return Math.max(0, maxFailures - count);
    }
}
