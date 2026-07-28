package com.icezhg.sky.pivot.config.redis;

import java.time.Duration;

public final class RedisKeyPrefix {

    public static final String NAMESPACE = "sky-pivot";

    public static final String LOGIN_ATTEMPTS = "login:attempts";
    public static final String LOGIN_LOCKED = "login:locked";
    public static final String OPRF_LIMIT = "oprf:limit";
    public static final String JWT_BLACKLIST = "jwt:blacklist";
    public static final String RECOVERY_CHALLENGE = "recovery:challenge";
    public static final String RECOVERY_USED = "recovery:used";

    public static final String MASTER_PASSWORD_ATTEMPTS = "master-password:attempts";

    public static final Duration TTL_LOGIN_ATTEMPTS = Duration.ofHours(1);
    public static final Duration TTL_OPRF_LIMIT = Duration.ofMinutes(1);
    public static final Duration TTL_RECOVERY_CHALLENGE = Duration.ofMinutes(5);
    public static final Duration TTL_RECOVERY_USED = Duration.ofMinutes(10);

    public static final Duration LOCKOUT_BASE = Duration.ofMinutes(15);
    public static final Duration LOCKOUT_STEP1 = Duration.ofMinutes(30);
    public static final Duration LOCKOUT_STEP2 = Duration.ofMinutes(60);
    public static final Duration LOCKOUT_MAX = Duration.ofMinutes(120);

    private RedisKeyPrefix() {
    }

    public static String key(String prefix, String... segments) {
        StringBuilder sb = new StringBuilder(NAMESPACE).append(':').append(prefix);
        for (String segment : segments) {
            sb.append(':').append(segment);
        }
        return sb.toString();
    }

    public static Duration lockoutDuration(int consecutiveLockouts) {
        return switch (consecutiveLockouts) {
            case 0, 1 -> LOCKOUT_BASE;
            case 2 -> LOCKOUT_STEP1;
            case 3 -> LOCKOUT_STEP2;
            default -> LOCKOUT_MAX;
        };
    }
}
