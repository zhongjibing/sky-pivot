package com.icezhg.sky.pivot.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.icezhg.sky.pivot.config.properties.SecurityProperties;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class BiometricLockoutService {

    private final Cache<Long, Integer> failureCount;
    private final int maxFailures;

    public BiometricLockoutService(SecurityProperties securityProperties) {
        this.maxFailures = securityProperties.getBiometricMaxFailures();
        this.failureCount = Caffeine.newBuilder()
            .expireAfterWrite(securityProperties.getBiometricLockoutMinutes(), TimeUnit.MINUTES)
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
