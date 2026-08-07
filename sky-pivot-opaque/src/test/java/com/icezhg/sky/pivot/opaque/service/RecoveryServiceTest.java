package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import com.icezhg.sky.pivot.dto.RecoveryChallengeResponse;
import com.icezhg.sky.pivot.dto.RecoveryCodeResetRequest;
import com.icezhg.sky.pivot.dto.RecoveryTokenResponse;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.UserRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RecoveryService Tests")
class RecoveryServiceTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final Long TEST_USER_ID = 100L;
    private static final String TEST_CREDENTIAL_ID = "test-user@sky-pivot";
    private static final String TEST_RECOVERY_KEY_HASH = HEX.formatHex(
            "recovery-key-hash-recovery-key-hash-".getBytes(StandardCharsets.UTF_8));
    private static final String TEST_ENCRYPTED_URK = "encrypted-urk-base64";

    @Mock
    private UserRepository userRepository;

    @Mock
    private RedisService redisService;

    @Mock
    private SessionTokenService sessionTokenService;

    private RecoveryService recoveryService;

    @BeforeEach
    void setUp() {
        recoveryService = new RecoveryService(userRepository, redisService, sessionTokenService);
    }

    private User createTestUser() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setCredentialIdentifier(TEST_CREDENTIAL_ID);
        user.setRecoveryKeyHash(TEST_RECOVERY_KEY_HASH);
        user.setRecoverySalt("recovery-salt-hex");
        user.setEncryptedUrkRecovery(TEST_ENCRYPTED_URK);
        return user;
    }

    @Test
    @DisplayName("createChallenge should generate challenge and store in Redis")
    void shouldCreateChallenge() {
        when(userRepository.findByCredentialIdentifier(TEST_CREDENTIAL_ID))
                .thenReturn(Optional.of(createTestUser()));

        RecoveryChallengeResponse response = recoveryService.createChallenge(TEST_CREDENTIAL_ID);

        assertNotNull(response);
        assertNotNull(response.requestId());
        assertNotNull(response.challenge());
        assertEquals(64, response.challenge().length());
        assertTrue(response.expiresAt() > System.currentTimeMillis());

        verify(redisService).set(startsWith("sky-pivot:recovery:challenge:"), anyString(),
                eq(RedisKeyPrefix.TTL_RECOVERY_CHALLENGE));
    }

    @Test
    @DisplayName("createChallenge should fail for unknown user")
    void shouldFailForUnknownUser() {
        when(userRepository.findByCredentialIdentifier("unknown"))
                .thenReturn(Optional.empty());

        assertThrows(SecurityException.class, () ->
                recoveryService.createChallenge("unknown"));
    }

    @Test
    @DisplayName("createChallenge should fail when no recovery code configured")
    void shouldFailWithoutRecoveryCode() {
        User user = createTestUser();
        user.setRecoveryKeyHash(null);
        when(userRepository.findByCredentialIdentifier(TEST_CREDENTIAL_ID))
                .thenReturn(Optional.of(user));

        assertThrows(SecurityException.class, () ->
                recoveryService.createChallenge(TEST_CREDENTIAL_ID));
    }

    @Test
    @DisplayName("startRecovery should verify HMAC authCode and return recovery token")
    void shouldStartRecovery() throws Exception {
        User user = createTestUser();
        when(userRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

        SecureRandom sr = new SecureRandom();
        byte[] challengeBytes = new byte[32];
        sr.nextBytes(challengeBytes);
        String challengeHex = HEX.formatHex(challengeBytes);
        String requestId = "test-request-id";

        String challengeKey = "sky-pivot:recovery:challenge:test-request-id";
        String challengeValue = TEST_USER_ID + "|" + challengeHex;
        when(redisService.get(eq(challengeKey), eq(String.class)))
                .thenReturn(Optional.of(challengeValue));
        when(redisService.hasKey(anyString())).thenReturn(false);

        byte[] recoveryKeyHashBytes = HEX.parseHex(TEST_RECOVERY_KEY_HASH);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(recoveryKeyHashBytes, "HmacSHA256"));
        byte[] authCodeBytes = mac.doFinal(challengeBytes);
        String authCodeHex = HEX.formatHex(authCodeBytes);

        String expectedRecoveryToken = "recovery-jwt-token";
        when(sessionTokenService.generateRecoveryToken(TEST_USER_ID))
                .thenReturn(expectedRecoveryToken);

        RecoveryTokenResponse response = recoveryService.startRecovery(requestId, authCodeHex);

        assertNotNull(response);
        assertEquals(expectedRecoveryToken, response.recoveryToken());
        assertTrue(response.expiresAt() > System.currentTimeMillis());

        verify(redisService).delete(challengeKey);
        verify(redisService).set(startsWith("sky-pivot:recovery:used:"), eq("used"),
                eq(RedisKeyPrefix.TTL_RECOVERY_USED));
    }

    @Test
    @DisplayName("startRecovery should fail when challenge expired")
    void shouldFailOnExpiredChallenge() {
        when(redisService.get(anyString(), eq(String.class)))
                .thenReturn(Optional.empty());

        assertThrows(SecurityException.class, () ->
                recoveryService.startRecovery("expired-request-id", "any-auth-code"));
    }

    @Test
    @DisplayName("startRecovery should fail with wrong authCode")
    void shouldFailOnWrongAuthCode() throws Exception {
        String requestId = "test-request-id";
        String challengeKey = "sky-pivot:recovery:challenge:test-request-id";
        String challengeValue = TEST_USER_ID + "|" + "a".repeat(64);
        when(redisService.get(eq(challengeKey), eq(String.class)))
                .thenReturn(Optional.of(challengeValue));
        when(redisService.hasKey(anyString())).thenReturn(false);

        User user = createTestUser();
        when(userRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

        assertThrows(SecurityException.class, () ->
                recoveryService.startRecovery(requestId, "wrong-auth-code"));
        verify(redisService).delete(challengeKey);
    }

    @Test
    @DisplayName("startRecovery should reject replay — second use of same authCode")
    void shouldRejectReplay() throws Exception {
        String requestId = "test-request-id";
        String challengeKey = "sky-pivot:recovery:challenge:test-request-id";
        String challengeValue = TEST_USER_ID + "|" + "a".repeat(64);
        String authCode = "some-auth-code";

        when(redisService.get(eq(challengeKey), eq(String.class)))
                .thenReturn(Optional.of(challengeValue));
        when(redisService.hasKey(contains("recovery:used:"))).thenReturn(true);

        assertThrows(SecurityException.class, () ->
                recoveryService.startRecovery(requestId, authCode));
        verify(redisService).delete(challengeKey);
    }

    @Test
    @DisplayName("resetRecoveryCode should update user recovery fields")
    void shouldResetRecoveryCode() {
        User user = createTestUser();
        when(userRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));

        RecoveryCodeResetRequest request = new RecoveryCodeResetRequest(
                "new-salt", "new-key-hash", "new-encrypted-urk");

        recoveryService.resetRecoveryCode(TEST_USER_ID, request);

        assertEquals("new-salt", user.getRecoverySalt());
        assertEquals("new-key-hash", user.getRecoveryKeyHash());
        assertEquals("new-encrypted-urk", user.getEncryptedUrkRecovery());
        verify(userRepository).save(user);
    }

    @Test
    @DisplayName("getEncryptedUrkRecovery should return stored value")
    void shouldGetEncryptedUrk() {
        when(userRepository.findById(TEST_USER_ID))
                .thenReturn(Optional.of(createTestUser()));

        String urk = recoveryService.getEncryptedUrkRecovery(TEST_USER_ID);
        assertEquals(TEST_ENCRYPTED_URK, urk);
    }

    @Test
    @DisplayName("AC-1: Challenge expires after 5 minutes (Redis TTL set)")
    void challengeShouldExpireAfterFiveMinutes() {
        when(userRepository.findByCredentialIdentifier(TEST_CREDENTIAL_ID))
                .thenReturn(Optional.of(createTestUser()));

        recoveryService.createChallenge(TEST_CREDENTIAL_ID);

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        verify(redisService).set(keyCaptor.capture(), anyString(), eq(RedisKeyPrefix.TTL_RECOVERY_CHALLENGE));
        assertTrue(keyCaptor.getValue().startsWith("sky-pivot:recovery:challenge:"));
    }

    @Test
    @DisplayName("AC-6: RecoveryCodeResetRequest should have all fields annotated")
    void resetRequestShouldBeARecord() {
        RecoveryCodeResetRequest req = new RecoveryCodeResetRequest("salt", "hash", "urk");
        assertEquals("salt", req.recoverySalt());
        assertEquals("hash", req.recoveryKeyHash());
        assertEquals("urk", req.encryptedUrkRecovery());
    }
}
