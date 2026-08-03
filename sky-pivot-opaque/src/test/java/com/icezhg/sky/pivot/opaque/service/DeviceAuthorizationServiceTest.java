package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import com.icezhg.sky.pivot.entity.Device;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.DeviceRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import com.icezhg.sky.pivot.opaque.service.DeviceAuthorizationService.EmergencyAuthChallengeData;
import com.icezhg.sky.pivot.opaque.service.DeviceAuthorizationService.EmergencyAuthResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@DisplayName("DeviceAuthorizationService Tests")
class DeviceAuthorizationServiceTest {

    private DeviceAuthorizationService authService;
    private FakeRedisService redisService;
    private DeviceRepository deviceRepository;
    private UserRepository userRepository;
    private DeviceService deviceService;

    private static final Long TEST_USER_ID = 200L;
    private static final String TEST_DEVICE_ID = "new-device-uuid";
    private static final String TEST_CRED_ID = "user@example.com";

    private static final String RECOVERY_KEY_HASH;

    static {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest("test-recovery-key-data".getBytes(StandardCharsets.UTF_8));
            RECOVERY_KEY_HASH = java.util.HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @BeforeEach
    void setUp() {
        redisService = new FakeRedisService();
        deviceRepository = mock(DeviceRepository.class);
        userRepository = mock(UserRepository.class);
        deviceService = mock(DeviceService.class);

        authService = new DeviceAuthorizationService(
                redisService, deviceRepository, userRepository, deviceService);
    }

    @Test
    @DisplayName("Level 2: Should initiate authorization and store TOTP")
    void shouldInitiateLevel2Auth() {
        String requestId = authService.initLevel2Auth(TEST_USER_ID,
                "temp-pub-key", "a1b2c3d4");

        assertNotNull(requestId);
        assertEquals(16, requestId.length());

        String tempKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TEMP_KEY, requestId);
        String tempData = redisService.get(tempKey, String.class).orElse(null);
        assertNotNull(tempData);
        assertTrue(tempData.contains(String.valueOf(TEST_USER_ID)));

        String totpKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TOTP, requestId);
        String totp = redisService.get(totpKey, String.class).orElse(null);
        assertNotNull(totp);
        assertEquals(6, totp.length());
    }

    @Test
    @DisplayName("Level 2: Should retrieve stored fingerprint")
    void shouldGetFingerprintForRequest() {
        String requestId = authService.initLevel2Auth(TEST_USER_ID,
                "temp-pub-key", "fingerprint-abc");

        String fingerprint = authService.getFingerprintForRequest(requestId);
        assertEquals("fingerprint-abc", fingerprint);
    }

    @Test
    @DisplayName("Level 2: Should retrieve stored temp public key")
    void shouldGetTempPublicKeyForRequest() {
        String requestId = authService.initLevel2Auth(TEST_USER_ID,
                "my-temp-key", "fingerprint");

        String tempKey = authService.getTempPublicKeyForRequest(requestId);
        assertEquals("my-temp-key", tempKey);
    }

    @Test
    @DisplayName("Level 2: Should retrieve user ID for request")
    void shouldGetUserIdForRequest() {
        String requestId = authService.initLevel2Auth(TEST_USER_ID,
                "temp-key", "fingerprint");

        Long userId = authService.getUserIdForRequest(requestId);
        assertEquals(TEST_USER_ID, userId);
    }

    @Test
    @DisplayName("Level 2: Should fail for expired/missing authorization request")
    void shouldFailForExpiredRequest() {
        assertThrows(SecurityException.class, () ->
                authService.getFingerprintForRequest("nonexistent-request"));
    }

    @Test
    @DisplayName("Level 2: Should verify valid TOTP")
    void shouldVerifyValidTotp() {
        String requestId = authService.initLevel2Auth(TEST_USER_ID,
                "temp-key", "fingerprint");

        String totpKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_AUTH_TOTP, requestId);
        String storedTotp = redisService.get(totpKey, String.class).orElse(null);

        boolean valid = authService.verifyTotp(requestId, storedTotp);
        assertTrue(valid);

        String totpAfter = redisService.get(totpKey, String.class).orElse(null);
        assertNull(totpAfter);
    }

    @Test
    @DisplayName("Level 2: Should reject invalid TOTP")
    void shouldRejectInvalidTotp() {
        String requestId = authService.initLevel2Auth(TEST_USER_ID,
                "temp-key", "fingerprint");

        boolean valid = authService.verifyTotp(requestId, "000000");
        assertFalse(valid);
    }

    @Test
    @DisplayName("Level 2: Should store and retrieve encrypted DEK")
    void shouldStoreAndRetrieveEncryptedDek() {
        String requestId = String.join("", "req", "00112233445566");
        authService.storeEncryptedDek(requestId, "encrypted-dek-data");

        String dek = authService.getEncryptedDek(requestId);
        assertEquals("encrypted-dek-data", dek);

        assertThrows(SecurityException.class, () ->
                authService.getEncryptedDek(requestId));
    }

    @Test
    @DisplayName("AC-6: Fingerprint should be SHA-256 first 8 hex chars")
    void shouldComputeFingerprintCorrectly() {
        String publicKey = "this-is-a-test-public-key-for-fingerprint-computation";
        String fingerprint = DeviceAuthorizationService.computeFingerprint(publicKey);

        assertNotNull(fingerprint);
        assertEquals(8, fingerprint.length());

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(publicKey.getBytes(StandardCharsets.UTF_8));
            String expected = java.util.HexFormat.of().formatHex(hash).substring(0, 8);
            assertEquals(expected, fingerprint);
        } catch (Exception e) {
            fail("Should not throw: " + e.getMessage());
        }
    }

    @Test
    @DisplayName("AC-3: Emergency auth challenge should be created successfully")
    void shouldInitEmergencyAuthChallenge() {
        User user = createUser();
        when(userRepository.findByCredentialIdentifier(TEST_CRED_ID))
                .thenReturn(Optional.of(user));

        EmergencyAuthChallengeData data = authService.initEmergencyAuth(TEST_CRED_ID);

        assertNotNull(data.requestId());
        assertNotNull(data.recoverySalt());
        assertNotNull(data.challenge());
        assertEquals(64, data.challenge().length());
        assertNotNull(data.expiresAt());
    }

    @Test
    @DisplayName("AC-3: Emergency auth challenge should fail for unknown user")
    void shouldFailChallengeForUnknownUser() {
        when(userRepository.findByCredentialIdentifier(TEST_CRED_ID))
                .thenReturn(Optional.empty());

        assertThrows(SecurityException.class, () ->
                authService.initEmergencyAuth(TEST_CRED_ID));
    }

    @Test
    @DisplayName("AC-3: Emergency auth should complete after valid challenge")
    void shouldCompleteEmergencyAuth() {
        User user = createUser();
        when(userRepository.findByCredentialIdentifier(TEST_CRED_ID))
                .thenReturn(Optional.of(user));
        when(userRepository.findById(TEST_USER_ID))
                .thenReturn(Optional.of(user));
        when(deviceRepository.findByUserIdAndDeviceId(TEST_USER_ID, TEST_DEVICE_ID))
                .thenReturn(Optional.empty());
        when(deviceService.activate(eq(TEST_USER_ID), eq(TEST_DEVICE_ID), any(), any(), any()))
                .thenReturn(createDevice());

        EmergencyAuthChallengeData challenge = authService.initEmergencyAuth(TEST_CRED_ID);

        EmergencyAuthResult result = authService.verifyEmergencyAuth(
                challenge.requestId(),
                RECOVERY_KEY_HASH,
                "123456",
                TEST_DEVICE_ID,
                "Emergency Phone",
                "MINIAPP",
                "pub-key"
        );

        assertTrue(result.authorized());
        assertTrue(result.emergencyMode());
        assertNotNull(result.expiresAt());
        assertTrue(result.requiresNewRecoveryCode());

        String sessionKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_EMERGENCY,
                TEST_USER_ID.toString(), TEST_DEVICE_ID);
        assertTrue(redisService.hasKey(sessionKey));
    }

    @Test
    @DisplayName("AC-3: Emergency auth should fail with wrong recovery key hash")
    void shouldFailEmergencyAuthWithWrongHash() {
        User user = createUser();
        when(userRepository.findByCredentialIdentifier(TEST_CRED_ID))
                .thenReturn(Optional.of(user));
        when(userRepository.findById(TEST_USER_ID))
                .thenReturn(Optional.of(user));

        EmergencyAuthChallengeData challenge = authService.initEmergencyAuth(TEST_CRED_ID);

        assertThrows(SecurityException.class, () ->
                authService.verifyEmergencyAuth(
                        challenge.requestId(),
                        "wrong-hash-value",
                        "123456",
                        TEST_DEVICE_ID,
                        "Phone",
                        "MINIAPP",
                        "pub-key"
                ));
    }

    @Test
    @DisplayName("AC-3: Emergency auth should fail with invalid SMS code")
    void shouldFailEmergencyAuthWithInvalidSmsCode() {
        User user = createUser();
        when(userRepository.findByCredentialIdentifier(TEST_CRED_ID))
                .thenReturn(Optional.of(user));
        when(userRepository.findById(TEST_USER_ID))
                .thenReturn(Optional.of(user));

        EmergencyAuthChallengeData challenge = authService.initEmergencyAuth(TEST_CRED_ID);

        assertThrows(SecurityException.class, () ->
                authService.verifyEmergencyAuth(
                        challenge.requestId(),
                        RECOVERY_KEY_HASH,
                        "abcd",
                        TEST_DEVICE_ID,
                        "Phone",
                        "MINIAPP",
                        "pub-key"
                ));
    }

    @Test
    @DisplayName("AC-3: Emergency auth should fail for already registered device")
    void shouldFailEmergencyAuthForExistingDevice() {
        User user = createUser();
        when(userRepository.findByCredentialIdentifier(TEST_CRED_ID))
                .thenReturn(Optional.of(user));
        when(userRepository.findById(TEST_USER_ID))
                .thenReturn(Optional.of(user));
        when(deviceRepository.findByUserIdAndDeviceId(TEST_USER_ID, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createDevice()));

        EmergencyAuthChallengeData challenge = authService.initEmergencyAuth(TEST_CRED_ID);

        assertThrows(SecurityException.class, () ->
                authService.verifyEmergencyAuth(
                        challenge.requestId(),
                        RECOVERY_KEY_HASH,
                        "123456",
                        TEST_DEVICE_ID,
                        "Phone",
                        "MINIAPP",
                        "pub-key"
                ));
    }

    @Test
    @DisplayName("AC-3: Emergency auth challenge should be single-use")
    void shouldRejectReusedChallenge() {
        User user = createUser();
        when(userRepository.findByCredentialIdentifier(TEST_CRED_ID))
                .thenReturn(Optional.of(user));
        when(userRepository.findById(TEST_USER_ID))
                .thenReturn(Optional.of(user));
        when(deviceRepository.findByUserIdAndDeviceId(eq(TEST_USER_ID), anyString()))
                .thenReturn(Optional.empty());
        when(deviceService.activate(eq(TEST_USER_ID), anyString(), any(), any(), any()))
                .thenReturn(createDevice());

        EmergencyAuthChallengeData challenge = authService.initEmergencyAuth(TEST_CRED_ID);

        authService.verifyEmergencyAuth(
                challenge.requestId(), RECOVERY_KEY_HASH, "123456",
                TEST_DEVICE_ID, "Phone", "MINIAPP", "pub-key"
        );

        assertThrows(SecurityException.class, () ->
                authService.verifyEmergencyAuth(
                        challenge.requestId(), RECOVERY_KEY_HASH, "123456",
                        "device-2", "Phone2", "MINIAPP", "pub-key2"
                ));
    }

    @Test
    @DisplayName("Should check emergency session active status")
    void shouldCheckEmergencySessionActive() {
        assertFalse(authService.isEmergencySessionActive(TEST_USER_ID, TEST_DEVICE_ID));

        String sessionKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_EMERGENCY,
                TEST_USER_ID.toString(), TEST_DEVICE_ID);
        redisService.set(sessionKey, "active", Duration.ofHours(1));

        assertTrue(authService.isEmergencySessionActive(TEST_USER_ID, TEST_DEVICE_ID));
    }

    private User createUser() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setCredentialIdentifier(TEST_CRED_ID);
        user.setRecoverySalt(Base64.getEncoder().encodeToString("test-salt-16-bytes".getBytes()));
        user.setRecoveryKeyHash(RECOVERY_KEY_HASH);
        return user;
    }

    private Device createDevice() {
        Device device = new Device();
        device.setId(1L);
        device.setUserId(TEST_USER_ID);
        device.setDeviceId(TEST_DEVICE_ID);
        device.setDeviceName("Test Device");
        device.setDeviceType("PC");
        device.setEd25519PublicKey("pub-key");
        device.setAuthorized(true);
        device.setRevoked(false);
        return device;
    }

    static class FakeRedisService extends RedisService {

        private final Map<String, Object> store = new ConcurrentHashMap<>();

        FakeRedisService() {
            super(null);
        }

        @Override
        public void set(String key, Object value, Duration timeout) {
            store.put(key, value);
        }

        @Override
        public Boolean hasKey(String key) {
            return store.containsKey(key);
        }

        @Override
        public <T> Optional<T> get(String key, Class<T> type) {
            @SuppressWarnings("unchecked")
            T value = (T) store.get(key);
            return Optional.ofNullable(value);
        }

        @Override
        public Boolean delete(String key) {
            return store.remove(key) != null;
        }
    }
}
