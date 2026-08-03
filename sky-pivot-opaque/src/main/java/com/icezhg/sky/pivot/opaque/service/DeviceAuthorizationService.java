package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import com.icezhg.sky.pivot.entity.Device;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.DeviceRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

@Service
public class DeviceAuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(DeviceAuthorizationService.class);
    private static final HexFormat HEX = HexFormat.of();
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final String EMERGENCY_CHALLENGE_PREFIX = "emerg:challenge";

    private final RedisService redisService;
    private final DeviceRepository deviceRepository;
    private final UserRepository userRepository;
    private final DeviceService deviceService;

    public DeviceAuthorizationService(RedisService redisService,
                                       DeviceRepository deviceRepository,
                                       UserRepository userRepository,
                                       DeviceService deviceService) {
        this.redisService = redisService;
        this.deviceRepository = deviceRepository;
        this.userRepository = userRepository;
        this.deviceService = deviceService;
    }

    public String initLevel2Auth(Long userId, String tempPublicKey, String fingerprint) {
        String requestId = DeviceService.generateRequestId();

        String tempKeyKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TEMP_KEY, requestId);
        String tempKeyData = userId + "|" + tempPublicKey + "|" + fingerprint;
        redisService.set(tempKeyKey, tempKeyData, RedisKeyPrefix.TTL_DEVICE_AUTH_TEMP_KEY);

        String totpCode = generateTotpCode();
        String totpKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TOTP, requestId);
        redisService.set(totpKey, totpCode, RedisKeyPrefix.TTL_DEVICE_AUTH_TOTP);

        log.info("Level 2 auth initiated: requestId={}, userId={}, fingerprint={}, totp={}",
                requestId, userId, fingerprint, totpCode);

        return requestId;
    }

    public String getFingerprintForRequest(String requestId) {
        String tempKeyKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TEMP_KEY, requestId);
        String data = redisService.get(tempKeyKey, String.class).orElse(null);
        if (data == null) {
            throw new SecurityException("Authorization request not found or expired: " + requestId);
        }
        String[] parts = data.split("\\|", 3);
        if (parts.length < 3) {
            throw new SecurityException("Invalid authorization request data");
        }
        return parts[2];
    }

    public String getTempPublicKeyForRequest(String requestId) {
        String tempKeyKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TEMP_KEY, requestId);
        String data = redisService.get(tempKeyKey, String.class).orElse(null);
        if (data == null) {
            throw new SecurityException("Authorization request not found or expired: " + requestId);
        }
        String[] parts = data.split("\\|", 3);
        if (parts.length < 2) {
            throw new SecurityException("Invalid authorization request data");
        }
        return parts[1];
    }

    public Long getUserIdForRequest(String requestId) {
        String tempKeyKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TEMP_KEY, requestId);
        String data = redisService.get(tempKeyKey, String.class).orElse(null);
        if (data == null) {
            throw new SecurityException("Authorization request not found or expired: " + requestId);
        }
        String[] parts = data.split("\\|", 3);
        if (parts.length < 1) {
            throw new SecurityException("Invalid authorization request data");
        }
        return Long.parseLong(parts[0]);
    }

    public boolean verifyTotp(String requestId, String totpCode) {
        String totpKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TOTP, requestId);
        String storedTotp = redisService.get(totpKey, String.class).orElse(null);
        if (storedTotp == null) {
            throw new SecurityException("TOTP code expired or not found for request: " + requestId);
        }
        boolean valid = storedTotp.equals(totpCode);
        if (valid) {
            redisService.delete(totpKey);
        }
        return valid;
    }

    public void storeEncryptedDek(String requestId, String encryptedDek) {
        String dekKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TEMP_KEY, requestId, "dek");
        redisService.set(dekKey, encryptedDek, Duration.ofMinutes(5));
    }

    public String getEncryptedDek(String requestId) {
        String dekKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TEMP_KEY, requestId, "dek");
        String encryptedDek = redisService.get(dekKey, String.class).orElse(null);
        if (encryptedDek == null) {
            throw new SecurityException("Encrypted DEK not found or expired for request: " + requestId);
        }
        redisService.delete(dekKey);
        return encryptedDek;
    }

    public EmergencyAuthChallengeData initEmergencyAuth(String credentialIdentifier) {
        User user = userRepository.findByCredentialIdentifier(credentialIdentifier)
                .orElseThrow(() -> new SecurityException("User not found"));

        String requestId = DeviceService.generateRequestId();
        byte[] challengeBytes = new byte[32];
        SECURE_RANDOM.nextBytes(challengeBytes);
        String challenge = HEX.formatHex(challengeBytes);

        byte[] keyHashBytes = HEX.parseHex(user.getRecoveryKeyHash());
        byte[] expectedAuthCode = computeHmac(keyHashBytes, challengeBytes);
        String expectedAuthCodeHex = HEX.formatHex(expectedAuthCode);

        String challengeKey = RedisKeyPrefix.key(EMERGENCY_CHALLENGE_PREFIX, requestId);
        String challengeData = user.getId() + "|" + expectedAuthCodeHex;
        redisService.set(challengeKey, challengeData, Duration.ofMinutes(5));

        log.info("Emergency auth challenge created: requestId={}, userId={}", requestId, user.getId());

        return new EmergencyAuthChallengeData(
                requestId,
                user.getRecoverySalt(),
                challenge,
                Instant.now().plus(Duration.ofMinutes(5)).toString()
        );
    }

    @Transactional
    public EmergencyAuthResult verifyEmergencyAuth(String requestId, String recoveryKeyHash,
                                                    String smsCode, String deviceId,
                                                    String deviceName, String deviceType,
                                                    String ed25519PublicKey) {
        String challengeKey = RedisKeyPrefix.key(EMERGENCY_CHALLENGE_PREFIX, requestId);
        String challengeData = redisService.get(challengeKey, String.class).orElse(null);
        if (challengeData == null) {
            throw new SecurityException("Emergency auth challenge not found or expired");
        }

        String[] parts = challengeData.split("\\|", 2);
        if (parts.length < 2) {
            throw new SecurityException("Invalid challenge data");
        }
        Long userId = Long.parseLong(parts[0]);

        if (!recoveryKeyHash.equals(userRepository.findById(userId)
                .map(User::getRecoveryKeyHash).orElse(""))) {
            throw new SecurityException("Invalid recovery code");
        }

        if (!verifySmsCode(smsCode)) {
            throw new SecurityException("Invalid SMS verification code");
        }

        if (deviceRepository.findByUserIdAndDeviceId(userId, deviceId).isPresent()) {
            throw new SecurityException("Device already registered");
        }

        redisService.delete(challengeKey);

        String sessionKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_EMERGENCY, userId.toString(), deviceId);
        redisService.set(sessionKey, "active", RedisKeyPrefix.TTL_DEVICE_EMERGENCY);

        Device device = deviceService.activate(userId, deviceId, deviceName, deviceType, ed25519PublicKey);
        deviceService.authorizeDevice(userId, deviceId);

        log.warn("EMERGENCY_AUTH: userId={}, deviceId={}, emergency session active until {}",
                userId, deviceId, Instant.now().plus(RedisKeyPrefix.TTL_DEVICE_EMERGENCY));

        return new EmergencyAuthResult(
                deviceId,
                true,
                true,
                Instant.now().plus(RedisKeyPrefix.TTL_DEVICE_EMERGENCY).toString(),
                null,
                true
        );
    }

    public boolean isEmergencySessionActive(Long userId, String deviceId) {
        String sessionKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_EMERGENCY, userId.toString(), deviceId);
        return redisService.hasKey(sessionKey);
    }

    public static String computeFingerprint(String publicKey) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(publicKey.getBytes(StandardCharsets.UTF_8));
            return HEX.formatHex(hash).substring(0, 8);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private byte[] computeHmac(byte[] key, byte[] data) {
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);
        return result;
    }

    private String generateTotpCode() {
        int code = SECURE_RANDOM.nextInt(900000) + 100000;
        return String.valueOf(code);
    }

    private boolean verifySmsCode(String smsCode) {
        if (smsCode == null || smsCode.length() != 6) {
            return false;
        }
        try {
            Integer.parseInt(smsCode);
        } catch (NumberFormatException e) {
            return false;
        }
        return true;
    }

    public record EmergencyAuthChallengeData(
            String requestId,
            String recoverySalt,
            String challenge,
            String expiresAt
    ) {}

    public record EmergencyAuthResult(
            String deviceId,
            boolean authorized,
            boolean emergencyMode,
            String expiresAt,
            String newRecoveryCode,
            boolean requiresNewRecoveryCode
    ) {}
}
