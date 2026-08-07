package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.SyncEntry;
import com.icezhg.sky.pivot.dto.SyncPushRequest;
import com.icezhg.sky.pivot.dto.SyncPushResponse;
import com.icezhg.sky.pivot.dto.SyncPullResponse;
import com.icezhg.sky.pivot.entity.SyncLog;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.SyncLogRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import com.icezhg.sky.pivot.security.DeviceSignatureService;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("SyncService Tests")
class SyncServiceTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final String TEST_DEVICE_ID = "sync-test-device-001";
    private static final Long TEST_USER_ID = 100L;
    private static final String TEST_DEVICE_KEY_HEX =
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";

    private static final byte[] BC_PKCS8_HEADER = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    };

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Mock
    private SyncLogRepository syncLogRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private DeviceSignatureService deviceSignatureService;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    private SyncService syncService;
    private PrivateKey devicePrivateKey;

    @BeforeEach
    void setUp() throws Exception {
        syncService = new SyncService(syncLogRepository, userRepository,
                deviceSignatureService, eventPublisher);

        byte[] seed = HEX.parseHex(TEST_DEVICE_KEY_HEX);
        Ed25519PrivateKeyParameters bcKey = new Ed25519PrivateKeyParameters(seed, 0);

        byte[] pkcs8Bytes = new byte[BC_PKCS8_HEADER.length + seed.length];
        System.arraycopy(BC_PKCS8_HEADER, 0, pkcs8Bytes, 0, BC_PKCS8_HEADER.length);
        System.arraycopy(seed, 0, pkcs8Bytes, BC_PKCS8_HEADER.length, seed.length);
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        devicePrivateKey = keyFactory.generatePrivate(pkcs8Spec);
    }

    private SyncEntry createSyncEntry(String opId, String operation, String targetId,
                                       long targetVersion, long clientTimestamp, long lamportClock) throws Exception {
        String targetType = "VAULT_ITEM";
        String content = opId + "|" + operation + "|" + targetId + "|"
                + targetType + "|" + targetVersion + "|"
                + clientTimestamp + "|" + lamportClock;

        byte[] contentBytes = content.getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign(devicePrivateKey);
        signer.update(contentBytes);
        String signature = B64E.encodeToString(signer.sign());

        return new SyncEntry(opId, operation, targetId, targetType,
                targetVersion, clientTimestamp, lamportClock, signature);
    }

    private User createTestUser(long syncVersion) {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setCredentialIdentifier("test-user");
        user.setSyncVersion(syncVersion);
        return user;
    }

    @Test
    @DisplayName("pushSync should persist entries and return response")
    void shouldPushAndPersistEntries() throws Exception {
        when(userRepository.findById(TEST_USER_ID))
                .thenReturn(Optional.of(createTestUser(5L)));

        SyncEntry entry1 = createSyncEntry(UUID.randomUUID().toString(), "CREATE",
                "item-1", 6L, 1000L, 6L);
        SyncEntry entry2 = createSyncEntry(UUID.randomUUID().toString(), "UPDATE",
                "item-2", 7L, 1001L, 7L);

        SyncPushRequest request = new SyncPushRequest(List.of(entry1, entry2));

        SyncPushResponse response = syncService.pushSync(TEST_USER_ID, TEST_DEVICE_ID, request);

        assertNotNull(response);
        assertEquals(2, response.acceptedCount());
        assertEquals(5L, response.currentSyncVersion());

        ArgumentCaptor<List<SyncLog>> captor = ArgumentCaptor.forClass(List.class);
        verify(syncLogRepository).saveAll(captor.capture());
        List<SyncLog> saved = captor.getValue();
        assertEquals(2, saved.size());
        assertEquals("item-1", saved.get(0).getTargetId());
        assertEquals("item-2", saved.get(1).getTargetId());

        verify(deviceSignatureService, times(2))
                .verifyContentSignature(eq(TEST_USER_ID), eq(TEST_DEVICE_ID), any(byte[].class), anyString());
        verify(eventPublisher).publishEvent(any(SyncEvent.class));
    }

    @Test
    @DisplayName("pushSync should verify device signature for each entry")
    void shouldVerifyEachEntrySignature() throws Exception {
        doThrow(new SecurityException("Bad signature"))
                .when(deviceSignatureService)
                .verifyContentSignature(anyLong(), anyString(), any(byte[].class), anyString());

        SyncEntry entry = createSyncEntry(UUID.randomUUID().toString(), "CREATE",
                "item-1", 6L, 1000L, 6L);
        SyncPushRequest request = new SyncPushRequest(List.of(entry));

        assertThrows(SecurityException.class, () ->
                syncService.pushSync(TEST_USER_ID, TEST_DEVICE_ID, request));

        verify(syncLogRepository, never()).saveAll(any());
    }

    @Test
    @DisplayName("pullSync should return entries since given version")
    void shouldPullEntriesSinceVersion() {
        when(userRepository.findById(TEST_USER_ID))
                .thenReturn(Optional.of(createTestUser(10L)));

        SyncLog log1 = new SyncLog();
        log1.setOpId("op-1");
        log1.setDeviceId("device-1");
        log1.setOperation("CREATE");
        log1.setTargetType("VAULT_ITEM");
        log1.setTargetId("item-1");
        log1.setTargetVersion(6L);
        log1.setClientTimestamp(1000L);
        log1.setServerTimestamp(1000L);
        log1.setLamportClock(6L);

        SyncLog log2 = new SyncLog();
        log2.setOpId("op-2");
        log2.setDeviceId("device-2");
        log2.setOperation("UPDATE");
        log2.setTargetType("VAULT_ITEM");
        log2.setTargetId("item-2");
        log2.setTargetVersion(7L);
        log2.setClientTimestamp(1001L);
        log2.setServerTimestamp(1002L);
        log2.setLamportClock(7L);

        when(syncLogRepository.findByUserIdAndTargetVersionGreaterThan(TEST_USER_ID, 5L))
                .thenReturn(List.of(log1, log2));

        SyncPullResponse response = syncService.pullSync(TEST_USER_ID, 5L);

        assertNotNull(response);
        assertEquals(2, response.entries().size());
        assertEquals(10L, response.currentSyncVersion());
        assertEquals("item-1", response.entries().get(0).targetId());
        assertEquals("item-2", response.entries().get(1).targetId());
    }

    @Test
    @DisplayName("pullSync should return empty list when no entries since version")
    void shouldReturnEmptyWhenNoEntriesSinceVersion() {
        when(userRepository.findById(TEST_USER_ID))
                .thenReturn(Optional.of(createTestUser(10L)));

        when(syncLogRepository.findByUserIdAndTargetVersionGreaterThan(TEST_USER_ID, 10L))
                .thenReturn(List.of());

        SyncPullResponse response = syncService.pullSync(TEST_USER_ID, 10L);

        assertNotNull(response);
        assertTrue(response.entries().isEmpty());
        assertEquals(10L, response.currentSyncVersion());
    }

    @Test
    @DisplayName("check should return current sync version")
    void shouldReturnCurrentSyncVersion() {
        when(userRepository.findById(TEST_USER_ID))
                .thenReturn(Optional.of(createTestUser(42L)));

        long version = syncService.getSyncVersion(TEST_USER_ID);

        assertEquals(42L, version);
    }

    @Test
    @DisplayName("recordOperation should persist entry with SERVER_DIRECT signature")
    void shouldRecordServerGeneratedOperation() {
        syncService.recordOperation(TEST_USER_ID, TEST_DEVICE_ID, "CREATE",
                "item-1", "VAULT_ITEM", 6L);

        ArgumentCaptor<SyncLog> captor = ArgumentCaptor.forClass(SyncLog.class);
        verify(syncLogRepository).save(captor.capture());

        SyncLog log = captor.getValue();
        assertEquals(TEST_USER_ID, log.getUserId());
        assertEquals(TEST_DEVICE_ID, log.getDeviceId());
        assertEquals("CREATE", log.getOperation());
        assertEquals("item-1", log.getTargetId());
        assertEquals("VAULT_ITEM", log.getTargetType());
        assertEquals(6L, log.getTargetVersion());
        assertEquals(SyncService.SERVER_GENERATED_SIGNATURE, log.getDeviceSignature());

        verify(eventPublisher).publishEvent(any(SyncEvent.class));
    }

    @Test
    @DisplayName("recordOperation should use SERVER deviceId when null")
    void shouldDefaultDeviceIdWhenNull() {
        syncService.recordOperation(TEST_USER_ID, null, "DELETE",
                "item-1", "VAULT_ITEM", 7L);

        ArgumentCaptor<SyncLog> captor = ArgumentCaptor.forClass(SyncLog.class);
        verify(syncLogRepository).save(captor.capture());

        assertEquals("SERVER", captor.getValue().getDeviceId());
    }

    @Test
    @DisplayName("archiveEntriesBefore should archive and delete old entries")
    void shouldArchiveOldEntries() {
        long cutoffTimestamp = System.currentTimeMillis() - 90L * 24 * 60 * 60 * 1000;
        when(syncLogRepository.archiveByServerTimestampBefore(cutoffTimestamp)).thenReturn(100);
        when(syncLogRepository.deleteByServerTimestampBefore(cutoffTimestamp)).thenReturn(100);

        int archived = syncService.archiveEntriesBefore(cutoffTimestamp);

        assertEquals(100, archived);
        verify(syncLogRepository).archiveByServerTimestampBefore(cutoffTimestamp);
        verify(syncLogRepository).deleteByServerTimestampBefore(cutoffTimestamp);
    }

    @Test
    @DisplayName("archiveEntriesBefore should not delete when nothing archived")
    void shouldNotDeleteWhenNothingArchived() {
        long cutoffTimestamp = System.currentTimeMillis() - 90L * 24 * 60 * 60 * 1000;
        when(syncLogRepository.archiveByServerTimestampBefore(cutoffTimestamp)).thenReturn(0);

        int archived = syncService.archiveEntriesBefore(cutoffTimestamp);

        assertEquals(0, archived);
        verify(syncLogRepository, never()).deleteByServerTimestampBefore(anyLong());
    }

    @Test
    @DisplayName("SyncEntry signedContentBytes should produce consistent output")
    void syncEntrySignedContentBytesShouldBeConsistent() {
        SyncEntry entry = new SyncEntry("op-1", "CREATE", "item-1", "VAULT_ITEM",
                5L, 1000L, 5L, "sig");

        byte[] content = entry.signedContentBytes();
        assertEquals("op-1|CREATE|item-1|VAULT_ITEM|5|1000|5",
                new String(content, StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("pushSync with empty entries should fail validation")
    void shouldRejectEmptyPushRequest() {
        var validator = jakarta.validation.Validation.buildDefaultValidatorFactory().getValidator();
        var violations = validator.validate(new SyncPushRequest(List.of()));
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().contains("entries")));
    }
}
