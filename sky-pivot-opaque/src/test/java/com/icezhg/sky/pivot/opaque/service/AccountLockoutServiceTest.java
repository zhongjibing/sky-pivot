package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AccountLockoutService Tests")
class AccountLockoutServiceTest {

    private static final Long TEST_USER_ID = 100L;

    @Mock
    private RedisService redisService;

    @Mock
    private NotificationService notificationService;

    private AccountLockoutService lockoutService;

    @BeforeEach
    void setUp() {
        lockoutService = new AccountLockoutService(redisService, notificationService);
    }

    @Test
    @DisplayName("checkAccountLocked should throw when account is locked")
    void shouldThrowWhenAccountLocked() {
        when(redisService.hasKey(startsWith("sky-pivot:login:locked:"))).thenReturn(true);

        assertThrows(SecurityException.class, () ->
                lockoutService.checkAccountLocked(TEST_USER_ID));
    }

    @Test
    @DisplayName("checkAccountLocked should not throw when account is not locked")
    void shouldNotThrowWhenNotLocked() {
        when(redisService.hasKey(startsWith("sky-pivot:login:locked:"))).thenReturn(false);

        assertDoesNotThrow(() -> lockoutService.checkAccountLocked(TEST_USER_ID));
    }

    @Test
    @DisplayName("recordFailedAttempt should increment counter")
    void shouldIncrementFailedAttempts() {
        when(redisService.increment(anyString())).thenReturn(1L);

        lockoutService.recordFailedAttempt(TEST_USER_ID);

        verify(redisService).increment(startsWith("sky-pivot:login:attempts:"));
        verify(redisService).expire(startsWith("sky-pivot:login:attempts:"),
                eq(RedisKeyPrefix.TTL_LOGIN_ATTEMPTS));
    }

    @Test
    @DisplayName("AC-2: 10th failed attempt should trigger account lock")
    void shouldLockOnTenthFailedAttempt() {
        when(redisService.increment(startsWith("sky-pivot:login:attempts:"))).thenReturn(10L);
        when(redisService.increment(startsWith("sky-pivot:login:consecutive-lockouts:"))).thenReturn(1L);

        lockoutService.recordFailedAttempt(TEST_USER_ID);

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        verify(redisService).set(keyCaptor.capture(), anyString(), any(Duration.class));
        assertTrue(keyCaptor.getValue().startsWith("sky-pivot:login:locked:"));

        verify(notificationService).sendAccountLockedNotification(eq(TEST_USER_ID), anyLong());
    }

    @Test
    @DisplayName("AC-3: Consecutive lockouts should escalate duration")
    void shouldEscalateConsecutiveLockouts() {
        when(redisService.increment(anyString()))
                .thenReturn(10L, 1L,
                        10L, 2L,
                        10L, 3L,
                        10L, 4L);

        lockoutService.recordFailedAttempt(TEST_USER_ID);
        lockoutService.recordFailedAttempt(TEST_USER_ID);
        lockoutService.recordFailedAttempt(TEST_USER_ID);
        lockoutService.recordFailedAttempt(TEST_USER_ID);

        ArgumentCaptor<Duration> durationCaptor = ArgumentCaptor.forClass(Duration.class);
        verify(redisService, times(4)).set(anyString(), anyString(), durationCaptor.capture());

        var durations = durationCaptor.getAllValues();
        assertEquals(RedisKeyPrefix.LOCKOUT_BASE.toMinutes(), durations.get(0).toMinutes());
        assertEquals(RedisKeyPrefix.LOCKOUT_STEP1.toMinutes(), durations.get(1).toMinutes());
        assertEquals(RedisKeyPrefix.LOCKOUT_STEP2.toMinutes(), durations.get(2).toMinutes());
        assertEquals(RedisKeyPrefix.LOCKOUT_MAX.toMinutes(), durations.get(3).toMinutes());
    }

    @Test
    @DisplayName("resetAttempts should clear counters")
    void shouldResetAttempts() {
        when(redisService.delete(anyString())).thenReturn(true);

        lockoutService.resetAttempts(TEST_USER_ID);

        verify(redisService, atLeast(2)).delete(anyString());
    }

    @Test
    @DisplayName("isCaptchaRequired should return true after 5 failures")
    void shouldRequireCaptchaAfterFiveFailures() {
        when(redisService.get(startsWith("sky-pivot:login:attempts:"), eq(String.class)))
                .thenReturn(java.util.Optional.of("5"));

        assertTrue(lockoutService.isCaptchaRequired(TEST_USER_ID));
    }

    @Test
    @DisplayName("isCaptchaRequired should return false when fewer than 5 failures")
    void shouldNotRequireCaptchaBeforeFiveFailures() {
        when(redisService.get(startsWith("sky-pivot:login:attempts:"), eq(String.class)))
                .thenReturn(java.util.Optional.of("3"));

        assertFalse(lockoutService.isCaptchaRequired(TEST_USER_ID));
    }

    @Test
    @DisplayName("getRemainingAttempts should return correct count")
    void shouldReturnRemainingAttempts() {
        when(redisService.get(startsWith("sky-pivot:login:attempts:"), eq(String.class)))
                .thenReturn(java.util.Optional.of("7"));
        when(redisService.hasKey(anyString())).thenReturn(false);

        assertEquals(3, lockoutService.getRemainingAttempts(TEST_USER_ID));
    }

    @Test
    @DisplayName("getRemainingAttempts should return 0 when locked")
    void shouldReturnZeroWhenLocked() {
        when(redisService.hasKey(startsWith("sky-pivot:login:locked:"))).thenReturn(true);

        assertEquals(0, lockoutService.getRemainingAttempts(TEST_USER_ID));
    }

    @Test
    @DisplayName("isLocked should return true when Redis has lock key")
    void shouldDetectLockedState() {
        when(redisService.hasKey(startsWith("sky-pivot:login:locked:"))).thenReturn(true);
        assertTrue(lockoutService.isLocked(TEST_USER_ID));
    }

    @Test
    @DisplayName("isLocked should return false when no lock key")
    void shouldDetectUnlockedState() {
        when(redisService.hasKey(startsWith("sky-pivot:login:locked:"))).thenReturn(false);
        assertFalse(lockoutService.isLocked(TEST_USER_ID));
    }
}
