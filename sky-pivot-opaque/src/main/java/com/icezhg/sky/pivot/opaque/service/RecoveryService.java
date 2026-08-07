package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import com.icezhg.sky.pivot.dto.RecoveryChallengeResponse;
import com.icezhg.sky.pivot.dto.RecoveryCodeResetRequest;
import com.icezhg.sky.pivot.dto.RecoveryTokenResponse;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.UserRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
public class RecoveryService {

    private static final Logger log = LoggerFactory.getLogger(RecoveryService.class);
    private static final HexFormat HEX = HexFormat.of();
    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final Duration AUTH_CODE_USED_TTL = Duration.ofMinutes(10);
    private static final long RECOVERY_TOKEN_DURATION_SECONDS = 5 * 60;

    private final UserRepository userRepository;
    private final RedisService redisService;
    private final SessionTokenService sessionTokenService;
    private final SecureRandom secureRandom = new SecureRandom();

    public RecoveryService(UserRepository userRepository, RedisService redisService,
                           SessionTokenService sessionTokenService) {
        this.userRepository = userRepository;
        this.redisService = redisService;
        this.sessionTokenService = sessionTokenService;
    }

    public RecoveryChallengeResponse createChallenge(String credentialIdentifier) {
        User user = userRepository.findByCredentialIdentifier(credentialIdentifier)
                .orElseThrow(() -> new SecurityException("User not found for credential: " + credentialIdentifier));

        if (user.getRecoveryKeyHash() == null || user.getRecoveryKeyHash().isBlank()) {
            throw new SecurityException("No recovery code configured for this account");
        }

        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        String challengeHex = HEX.formatHex(challengeBytes);

        String requestId = UUID.randomUUID().toString();

        String challengeKey = RedisKeyPrefix.key(RedisKeyPrefix.RECOVERY_CHALLENGE, requestId);
        String challengeValue = user.getId() + "|" + challengeHex;
        redisService.set(challengeKey, challengeValue, CHALLENGE_TTL);

        long expiresAt = Instant.now().plus(CHALLENGE_TTL).toEpochMilli();

        log.info("Recovery challenge created: requestId={}, userId={}", requestId, user.getId());
        return new RecoveryChallengeResponse(requestId, challengeHex, expiresAt);
    }

    public RecoveryTokenResponse startRecovery(String requestId, String authCode) {
        String challengeKey = RedisKeyPrefix.key(RedisKeyPrefix.RECOVERY_CHALLENGE, requestId);
        String challengeValue = redisService.get(challengeKey, String.class).orElse(null);

        if (challengeValue == null) {
            throw new SecurityException("Challenge expired or not found");
        }

        String[] parts = challengeValue.split("\\|", 2);
        if (parts.length != 2) {
            redisService.delete(challengeKey);
            throw new SecurityException("Invalid challenge data");
        }

        Long userId;
        String challengeHex;
        try {
            userId = Long.parseLong(parts[0]);
            challengeHex = parts[1];
        } catch (NumberFormatException e) {
            redisService.delete(challengeKey);
            throw new SecurityException("Invalid challenge data");
        }

        byte[] challengeBytes = parseHexSafely(challengeHex);

        String authCodeUsedKey = RedisKeyPrefix.key(RedisKeyPrefix.RECOVERY_USED, authCode);
        if (redisService.hasKey(authCodeUsedKey)) {
            redisService.delete(challengeKey);
            throw new SecurityException("Auth code has already been used — replay detected");
        }

        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new SecurityException("User not found"));

            if (user.getRecoveryKeyHash() == null || user.getRecoveryKeyHash().isBlank()) {
                throw new SecurityException("No recovery code configured for this account");
            }

            byte[] recoveryKeyHashBytes = parseHexSafely(user.getRecoveryKeyHash());
            byte[] expectedAuthCode = hmacSha256(recoveryKeyHashBytes, challengeBytes);
            byte[] submittedAuthCode = parseHexSafely(authCode);

            if (!java.util.Arrays.equals(expectedAuthCode, submittedAuthCode)) {
                throw new SecurityException("Invalid recovery code");
            }

            redisService.set(authCodeUsedKey, "used", AUTH_CODE_USED_TTL);

            String recoveryToken = sessionTokenService.generateRecoveryToken(userId);
            long expiresAt = Instant.now().plusSeconds(RECOVERY_TOKEN_DURATION_SECONDS).toEpochMilli();

            log.warn("Recovery authentication successful for userId={}", userId);
            return new RecoveryTokenResponse(recoveryToken, expiresAt);
        } catch (SecurityException e) {
            redisService.set(authCodeUsedKey, "used", AUTH_CODE_USED_TTL);
            throw e;
        } finally {
            redisService.delete(challengeKey);
        }
    }

    @Transactional
    public void resetRecoveryCode(Long userId, RecoveryCodeResetRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new SecurityException("User not found"));

        user.setRecoverySalt(request.recoverySalt());
        user.setRecoveryKeyHash(request.recoveryKeyHash());
        user.setEncryptedUrkRecovery(request.encryptedUrkRecovery());

        userRepository.save(user);

        log.warn("Recovery code reset for userId={}", userId);
    }

    public String getEncryptedUrkRecovery(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new SecurityException("User not found"));
        return user.getEncryptedUrkRecovery();
    }

    private byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            mac.init(keySpec);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 computation failed", e);
        }
    }

    private byte[] parseHexSafely(String hex) {
        try {
            return HEX.parseHex(hex);
        } catch (IllegalArgumentException e) {
            throw new SecurityException("Invalid hex encoding", e);
        }
    }
}
