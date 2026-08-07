package com.icezhg.sky.pivot.config;

import com.icezhg.sky.pivot.opaque.service.AccessTokenService;
import com.icezhg.sky.pivot.service.DeviceAuthRequestedEvent;
import com.icezhg.sky.pivot.service.DeviceRevokedEvent;
import com.icezhg.sky.pivot.service.EmergencyAuthUsedEvent;
import com.icezhg.sky.pivot.service.MasterPasswordChangedEvent;
import com.icezhg.sky.pivot.service.RecoveryCodeResetEvent;
import com.icezhg.sky.pivot.service.SyncEvent;
import com.icezhg.sky.pivot.dto.SyncLogEntry;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

import java.net.URI;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@DisplayName("SyncWebSocketHandler Tests")
class SyncWebSocketHandlerTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final String TEST_KEY_HEX =
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
    private static final String TEST_DEVICE_ID = "test-device-001";
    private static final String TEST_DEVICE_ID_2 = "test-device-002";

    private static final byte[] BC_PKCS8_HEADER = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    };

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private AccessTokenService accessTokenService;
    private SyncWebSocketHandler handler;
    private PrivateKey signingKey;

    @BeforeEach
    void setUp() throws Exception {
        accessTokenService = mock(AccessTokenService.class);
        handler = new SyncWebSocketHandler(accessTokenService);

        byte[] seed = HEX.parseHex(TEST_KEY_HEX);
        byte[] pkcs8Bytes = new byte[BC_PKCS8_HEADER.length + seed.length];
        System.arraycopy(BC_PKCS8_HEADER, 0, pkcs8Bytes, 0, BC_PKCS8_HEADER.length);
        System.arraycopy(seed, 0, pkcs8Bytes, BC_PKCS8_HEADER.length, seed.length);
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        signingKey = keyFactory.generatePrivate(pkcs8Spec);
    }

    @AfterEach
    void tearDown() {
        handler = null;
    }

    private String generateValidAt(Long userId, String deviceId, long ttlSeconds) {
        Instant now = Instant.now();
        return Jwts.builder()
                .header().add("alg", "EdDSA").and()
                .subject(userId.toString())
                .claim("did", deviceId)
                .claim("type", "AT")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ttlSeconds)))
                .id(UUID.randomUUID().toString())
                .signWith(signingKey, Jwts.SIG.EdDSA)
                .compact();
    }

    private Claims buildClaims(Long userId, String deviceId, Instant expiresAt) {
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn(userId.toString());
        when(claims.get("did", String.class)).thenReturn(deviceId);
        if (expiresAt != null) {
            when(claims.getExpiration()).thenReturn(Date.from(expiresAt));
        }
        return claims;
    }

    private WebSocketSession createMockSession(String sessionId, String token) {
        WebSocketSession session = mock(WebSocketSession.class);
        Map<String, Object> attrs = new ConcurrentHashMap<>();
        when(session.getId()).thenReturn(sessionId);
        when(session.getAttributes()).thenReturn(attrs);
        when(session.isOpen()).thenReturn(true);
        try {
            when(session.getUri()).thenReturn(new URI("ws://localhost/ws/sync?token=" + token));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return session;
    }

    @Test
    @DisplayName("AC-1: Valid AT should establish connection")
    void shouldEstablishConnectionWithValidAt() throws Exception {
        Long userId = 42L;
        String at = generateValidAt(userId, TEST_DEVICE_ID, 7200);
        Claims claims = buildClaims(userId, TEST_DEVICE_ID, Instant.now().plusSeconds(7200));
        when(accessTokenService.verifyAccessToken(at)).thenReturn(claims);

        WebSocketSession session = createMockSession("session-1", at);
        handler.afterConnectionEstablished(session);

        assertEquals(userId, session.getAttributes().get("userId"));
        assertEquals(TEST_DEVICE_ID, session.getAttributes().get("deviceId"));
        assertNotNull(session.getAttributes().get("atExpiresAtMs"));
        verify(accessTokenService).verifyAccessToken(at);
        verify(session, never()).close(any());
    }

    @Test
    @DisplayName("AC-1: Invalid AT should close connection with NOT_ACCEPTABLE")
    void shouldRejectConnectionWithInvalidAt() throws Exception {
        String at = "invalid-token";
        when(accessTokenService.verifyAccessToken(at))
                .thenThrow(new SecurityException("Invalid token"));

        WebSocketSession session = createMockSession("session-2", at);
        handler.afterConnectionEstablished(session);

        verify(session).close(CloseStatus.NOT_ACCEPTABLE);
        assertNull(session.getAttributes().get("userId"));
    }

    @Test
    @DisplayName("AC-1: Missing token should close connection with POLICY_VIOLATION")
    void shouldRejectConnectionWithoutToken() throws Exception {
        WebSocketSession session = mock(WebSocketSession.class);
        Map<String, Object> attrs = new ConcurrentHashMap<>();
        when(session.getAttributes()).thenReturn(attrs);
        when(session.isOpen()).thenReturn(true);
        try {
            when(session.getUri()).thenReturn(new URI("ws://localhost/ws/sync"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        handler.afterConnectionEstablished(session);

        verify(session).close(CloseStatus.POLICY_VIOLATION);
        verify(accessTokenService, never()).verifyAccessToken(anyString());
    }

    @Test
    @DisplayName("AC-2: Expired AT should trigger FORCE_LOGOUT")
    void shouldForceLogoutOnExpiredAt() throws Exception {
        Long userId = 42L;
        Instant soon = Instant.now().minusSeconds(10);
        String at = generateValidAt(userId, TEST_DEVICE_ID, 5);
        Claims claims = buildClaims(userId, TEST_DEVICE_ID, soon);
        when(accessTokenService.verifyAccessToken(at)).thenReturn(claims);

        WebSocketSession session = createMockSession("session-3", at);
        handler.afterConnectionEstablished(session);

        handler.handleTextMessage(session, new TextMessage("ping"));

        verify(session, timeout(1000)).close(argThat(status ->
                status.getCode() == 4001 &&
                "FORCE_LOGOUT".equals(status.getReason())));
    }

    @Test
    @DisplayName("Ping should receive pong response")
    void shouldRespondPongOnPing() throws Exception {
        Long userId = 42L;
        String at = generateValidAt(userId, TEST_DEVICE_ID, 7200);
        Claims claims = buildClaims(userId, TEST_DEVICE_ID, Instant.now().plusSeconds(7200));
        when(accessTokenService.verifyAccessToken(at)).thenReturn(claims);

        WebSocketSession session = createMockSession("session-4", at);
        handler.afterConnectionEstablished(session);

        handler.handleTextMessage(session, new TextMessage("ping"));

        verify(session, timeout(500)).sendMessage(
                argThat(msg -> msg instanceof TextMessage &&
                        "pong".equals(((TextMessage) msg).getPayload())));
    }

    @Test
    @DisplayName("AC-4: SyncEvent should broadcast SYNC message to user sessions")
    void shouldBroadcastSyncOnSyncEvent() throws Exception {
        Long userId = 42L;
        String at = generateValidAt(userId, TEST_DEVICE_ID, 7200);
        Claims claims = buildClaims(userId, TEST_DEVICE_ID, Instant.now().plusSeconds(7200));
        when(accessTokenService.verifyAccessToken(at)).thenReturn(claims);

        WebSocketSession session1 = createMockSession("session-sync-1", at);
        WebSocketSession session2 = createMockSession("session-sync-2", at);

        handler.afterConnectionEstablished(session1);
        handler.afterConnectionEstablished(session2);

        SyncLogEntry entry = new SyncLogEntry("op-1", "dev-1", "create", "vault_item",
                "item-001", 1L, System.currentTimeMillis(), System.currentTimeMillis(), 1L);

        SyncEvent event = new SyncEvent(userId, 5L, List.of(entry));
        handler.onSyncEvent(event);

        Thread.sleep(200);

        verify(session1, timeout(500)).sendMessage(
                argThat(msg -> msg instanceof TextMessage &&
                        ((TextMessage) msg).getPayload().contains("SYNC") &&
                        ((TextMessage) msg).getPayload().contains("5")));
        verify(session2, timeout(500)).sendMessage(
                argThat(msg -> msg instanceof TextMessage &&
                        ((TextMessage) msg).getPayload().contains("SYNC")));
    }

    @Test
    @DisplayName("AC-5: DeviceRevokedEvent should broadcast DEVICE_REVOKED to all devices")
    void shouldBroadcastDeviceRevokedToAllDevices() throws Exception {
        Long userId = 42L;
        String at = generateValidAt(userId, TEST_DEVICE_ID, 7200);
        Claims claims = buildClaims(userId, TEST_DEVICE_ID, Instant.now().plusSeconds(7200));
        when(accessTokenService.verifyAccessToken(at)).thenReturn(claims);

        WebSocketSession session = createMockSession("session-revoked-1", at);
        handler.afterConnectionEstablished(session);

        DeviceRevokedEvent event = new DeviceRevokedEvent(userId, TEST_DEVICE_ID_2, "My Phone");
        handler.onDeviceRevoked(event);

        Thread.sleep(200);

        verify(session, timeout(500)).sendMessage(
                argThat(msg -> msg instanceof TextMessage &&
                        ((TextMessage) msg).getPayload().contains("DEVICE_REVOKED") &&
                        ((TextMessage) msg).getPayload().contains(TEST_DEVICE_ID_2) &&
                        ((TextMessage) msg).getPayload().contains("My Phone")));
    }

    @Test
    @DisplayName("DeviceAuthRequestedEvent should broadcast DEVICE_AUTH_REQ")
    void shouldBroadcastDeviceAuthRequested() throws Exception {
        Long userId = 42L;
        String at = generateValidAt(userId, TEST_DEVICE_ID, 7200);
        Claims claims = buildClaims(userId, TEST_DEVICE_ID, Instant.now().plusSeconds(7200));
        when(accessTokenService.verifyAccessToken(at)).thenReturn(claims);

        WebSocketSession session = createMockSession("session-auth-req-1", at);
        handler.afterConnectionEstablished(session);

        DeviceAuthRequestedEvent event = new DeviceAuthRequestedEvent(
                userId, "req-123", "Chrome Browser", "abc12345");
        handler.onDeviceAuthRequested(event);

        Thread.sleep(200);

        verify(session, timeout(500)).sendMessage(
                argThat(msg -> msg instanceof TextMessage &&
                        ((TextMessage) msg).getPayload().contains("DEVICE_AUTH_REQ") &&
                        ((TextMessage) msg).getPayload().contains("req-123") &&
                        ((TextMessage) msg).getPayload().contains("abc12345")));
    }

    @Test
    @DisplayName("MasterPasswordChangedEvent should broadcast MASTER_PASSWORD_CHANGED")
    void shouldBroadcastMasterPasswordChanged() throws Exception {
        Long userId = 42L;
        String at = generateValidAt(userId, TEST_DEVICE_ID, 7200);
        Claims claims = buildClaims(userId, TEST_DEVICE_ID, Instant.now().plusSeconds(7200));
        when(accessTokenService.verifyAccessToken(at)).thenReturn(claims);

        WebSocketSession session = createMockSession("session-mp-1", at);
        handler.afterConnectionEstablished(session);

        MasterPasswordChangedEvent event = new MasterPasswordChangedEvent(userId);
        handler.onMasterPasswordChanged(event);

        Thread.sleep(200);

        verify(session, timeout(500)).sendMessage(
                argThat(msg -> msg instanceof TextMessage &&
                        ((TextMessage) msg).getPayload().contains("MASTER_PASSWORD_CHANGED")));
    }

    @Test
    @DisplayName("RecoveryCodeResetEvent should broadcast RECOVERY_CODE_RESET")
    void shouldBroadcastRecoveryCodeReset() throws Exception {
        Long userId = 42L;
        String at = generateValidAt(userId, TEST_DEVICE_ID, 7200);
        Claims claims = buildClaims(userId, TEST_DEVICE_ID, Instant.now().plusSeconds(7200));
        when(accessTokenService.verifyAccessToken(at)).thenReturn(claims);

        WebSocketSession session = createMockSession("session-rc-1", at);
        handler.afterConnectionEstablished(session);

        RecoveryCodeResetEvent event = new RecoveryCodeResetEvent(userId);
        handler.onRecoveryCodeReset(event);

        Thread.sleep(200);

        verify(session, timeout(500)).sendMessage(
                argThat(msg -> msg instanceof TextMessage &&
                        ((TextMessage) msg).getPayload().contains("RECOVERY_CODE_RESET")));
    }

    @Test
    @DisplayName("EmergencyAuthUsedEvent should broadcast EMERGENCY_AUTH_USED")
    void shouldBroadcastEmergencyAuthUsed() throws Exception {
        Long userId = 42L;
        String at = generateValidAt(userId, TEST_DEVICE_ID, 7200);
        Claims claims = buildClaims(userId, TEST_DEVICE_ID, Instant.now().plusSeconds(7200));
        when(accessTokenService.verifyAccessToken(at)).thenReturn(claims);

        WebSocketSession session = createMockSession("session-ea-1", at);
        handler.afterConnectionEstablished(session);

        EmergencyAuthUsedEvent event = new EmergencyAuthUsedEvent(
                userId, TEST_DEVICE_ID_2, "Rescue Device");
        handler.onEmergencyAuthUsed(event);

        Thread.sleep(200);

        verify(session, timeout(500)).sendMessage(
                argThat(msg -> msg instanceof TextMessage &&
                        ((TextMessage) msg).getPayload().contains("EMERGENCY_AUTH_USED") &&
                        ((TextMessage) msg).getPayload().contains(TEST_DEVICE_ID_2)));
    }

    @Test
    @DisplayName("DEVICE_REVOKED should be sent to all devices including revoked one")
    void shouldSendDeviceRevokedToAllIncludingRevoked() throws Exception {
        Long userId = 42L;
        String at1 = generateValidAt(userId, TEST_DEVICE_ID, 7200);
        String at2 = generateValidAt(userId, TEST_DEVICE_ID_2, 7200);
        Claims claims1 = buildClaims(userId, TEST_DEVICE_ID, Instant.now().plusSeconds(7200));
        Claims claims2 = buildClaims(userId, TEST_DEVICE_ID_2, Instant.now().plusSeconds(7200));
        when(accessTokenService.verifyAccessToken(at1)).thenReturn(claims1);
        when(accessTokenService.verifyAccessToken(at2)).thenReturn(claims2);

        WebSocketSession session1 = createMockSession("session-all-1", at1);
        WebSocketSession session2 = createMockSession("session-all-2", at2);
        handler.afterConnectionEstablished(session1);
        handler.afterConnectionEstablished(session2);

        DeviceRevokedEvent event = new DeviceRevokedEvent(userId, TEST_DEVICE_ID, "Device 1");
        handler.onDeviceRevoked(event);

        Thread.sleep(200);

        verify(session1, timeout(500)).sendMessage(any(TextMessage.class));
        verify(session2, timeout(500)).sendMessage(any(TextMessage.class));
    }

    @Test
    @DisplayName("Connection close should clean up session tracking")
    void shouldCleanUpOnConnectionClose() throws Exception {
        Long userId = 42L;
        String at = generateValidAt(userId, TEST_DEVICE_ID, 7200);
        Claims claims = buildClaims(userId, TEST_DEVICE_ID, Instant.now().plusSeconds(7200));
        when(accessTokenService.verifyAccessToken(at)).thenReturn(claims);

        WebSocketSession session = createMockSession("session-cleanup", at);
        handler.afterConnectionEstablished(session);

        handler.afterConnectionClosed(session, CloseStatus.NORMAL);

        DeviceRevokedEvent event = new DeviceRevokedEvent(userId, TEST_DEVICE_ID_2, "Other");
        handler.onDeviceRevoked(event);
        Thread.sleep(200);

        verify(session, never()).sendMessage(any(TextMessage.class));
    }
}
