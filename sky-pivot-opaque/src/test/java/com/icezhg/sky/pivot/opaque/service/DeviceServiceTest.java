package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import com.icezhg.sky.pivot.entity.Device;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.DeviceRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@DisplayName("DeviceService Tests")
class DeviceServiceTest {

    private DeviceService deviceService;
    private DeviceRepository deviceRepository;
    private UserRepository userRepository;
    private FakeRedisService redisService;

    private static final Long TEST_USER_ID = 100L;
    private static final String TEST_DEVICE_ID = "device-uuid-001";
    private static final String TEST_DEVICE_NAME = "My PC";
    private static final String TEST_DEVICE_TYPE = "PC";
    private static final String TEST_PUBLIC_KEY = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qga2V5";

    @BeforeEach
    void setUp() {
        deviceRepository = mock(DeviceRepository.class);
        userRepository = mock(UserRepository.class);
        redisService = new FakeRedisService();
        deviceService = new DeviceService(deviceRepository, userRepository, redisService);

        User user = new User();
        user.setId(TEST_USER_ID);
        when(userRepository.findById(TEST_USER_ID)).thenReturn(Optional.of(user));
        when(deviceRepository.save(any(Device.class))).thenAnswer(inv -> {
            Device d = inv.getArgument(0);
            if (d.getId() == null) d.setId(1L);
            return d;
        });
    }

    @Test
    @DisplayName("AC-1: First device activation should set authorized=true")
    void shouldAutoAuthorizeFirstDevice() {
        when(deviceRepository.findByUserId(TEST_USER_ID)).thenReturn(List.of());
        when(deviceRepository.findByUserIdAndDeviceId(TEST_USER_ID, TEST_DEVICE_ID))
                .thenReturn(Optional.empty());

        Device result = deviceService.activate(TEST_USER_ID, TEST_DEVICE_ID,
                TEST_DEVICE_NAME, TEST_DEVICE_TYPE, TEST_PUBLIC_KEY);

        assertTrue(result.getAuthorized());
        assertFalse(result.getRevoked());
        assertEquals(TEST_DEVICE_ID, result.getDeviceId());
        assertEquals(TEST_DEVICE_NAME, result.getDeviceName());
        assertEquals(TEST_DEVICE_TYPE, result.getDeviceType());
        assertEquals(TEST_PUBLIC_KEY, result.getEd25519PublicKey());
    }

    @Test
    @DisplayName("AC-1: Second device activation should set authorized=false until authorized")
    void shouldNotAutoAuthorizeSubsequentDevices() {
        Device existingAuthDevice = createDevice("existing-device", true, false);
        when(deviceRepository.findByUserId(TEST_USER_ID))
                .thenReturn(List.of(existingAuthDevice));
        when(deviceRepository.findByUserIdAndDeviceId(TEST_USER_ID, TEST_DEVICE_ID))
                .thenReturn(Optional.empty());

        Device result = deviceService.activate(TEST_USER_ID, TEST_DEVICE_ID,
                TEST_DEVICE_NAME, TEST_DEVICE_TYPE, TEST_PUBLIC_KEY);

        assertFalse(result.getAuthorized());
    }

    @Test
    @DisplayName("AC-1: Reactivating existing device should preserve authorized state")
    void shouldReactivateExistingDevice() {
        Device existing = createDevice(TEST_DEVICE_ID, true, false);
        when(deviceRepository.findByUserId(TEST_USER_ID))
                .thenReturn(List.of(existing));
        when(deviceRepository.findByUserIdAndDeviceId(TEST_USER_ID, TEST_DEVICE_ID))
                .thenReturn(Optional.of(existing));

        Device result = deviceService.activate(TEST_USER_ID, TEST_DEVICE_ID,
                "New Name", "MINIAPP", "new-key");

        assertEquals("New Name", result.getDeviceName());
        assertEquals("MINIAPP", result.getDeviceType());
        assertEquals("new-key", result.getEd25519PublicKey());
        assertTrue(result.getAuthorized());
        assertFalse(result.getRevoked());
    }

    @Test
    @DisplayName("Should authorize a device that was pending")
    void shouldAuthorizePendingDevice() {
        Device pending = createDevice(TEST_DEVICE_ID, false, false);
        when(deviceRepository.findByUserIdAndDeviceId(TEST_USER_ID, TEST_DEVICE_ID))
                .thenReturn(Optional.of(pending));

        deviceService.authorizeDevice(TEST_USER_ID, TEST_DEVICE_ID);

        assertTrue(pending.getAuthorized());
    }

    @Test
    @DisplayName("Should list all devices for a user")
    void shouldListDevices() {
        Device d1 = createDevice("device-1", true, false);
        Device d2 = createDevice("device-2", false, true);
        when(deviceRepository.findByUserId(TEST_USER_ID))
                .thenReturn(List.of(d1, d2));

        List<Device> devices = deviceService.listDevices(TEST_USER_ID);

        assertEquals(2, devices.size());
    }

    @Test
    @DisplayName("AC-5: Revoking a device should set revoked=true and add to Redis blacklist")
    void shouldRevokeDevice() {
        Device device = createDevice(TEST_DEVICE_ID, true, false);
        when(deviceRepository.findByUserIdAndDeviceId(TEST_USER_ID, TEST_DEVICE_ID))
                .thenReturn(Optional.of(device));

        deviceService.revoke(TEST_USER_ID, TEST_DEVICE_ID);

        assertTrue(device.getRevoked());
        assertFalse(device.getAuthorized());
        assertNotNull(device.getRevokedAt());

        String blacklistKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_BLACKLIST,
                TEST_USER_ID.toString(), TEST_DEVICE_ID);
        assertTrue(redisService.hasKey(blacklistKey));
    }

    @Test
    @DisplayName("AC-5: Revoking already revoked device should be idempotent")
    void shouldBeIdempotentWhenRevokingAlreadyRevokedDevice() {
        Device device = createDevice(TEST_DEVICE_ID, false, true);
        when(deviceRepository.findByUserIdAndDeviceId(TEST_USER_ID, TEST_DEVICE_ID))
                .thenReturn(Optional.of(device));

        deviceService.revoke(TEST_USER_ID, TEST_DEVICE_ID);

        assertTrue(device.getRevoked());
    }

    @Test
    @DisplayName("Should check device blacklist status")
    void shouldCheckDeviceBlacklist() {
        assertFalse(deviceService.isDeviceRevoked(TEST_USER_ID, TEST_DEVICE_ID));

        String blacklistKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_BLACKLIST,
                TEST_USER_ID.toString(), TEST_DEVICE_ID);
        redisService.set(blacklistKey, "revoked", Duration.ofHours(3));

        assertTrue(deviceService.isDeviceRevoked(TEST_USER_ID, TEST_DEVICE_ID));
    }

    @Test
    @DisplayName("Should update last seen timestamp")
    void shouldUpdateLastSeen() {
        Device device = createDevice(TEST_DEVICE_ID, true, false);
        device.setLastSeen(null);
        when(deviceRepository.findByUserIdAndDeviceId(TEST_USER_ID, TEST_DEVICE_ID))
                .thenReturn(Optional.of(device));

        deviceService.updateLastSeen(TEST_USER_ID, TEST_DEVICE_ID);

        assertNotNull(device.getLastSeen());
    }

    @Test
    @DisplayName("Should fail when activating for non-existent user")
    void shouldFailForNonExistentUser() {
        when(userRepository.findById(TEST_USER_ID)).thenReturn(Optional.empty());

        assertThrows(SecurityException.class, () ->
                deviceService.activate(TEST_USER_ID, TEST_DEVICE_ID,
                        TEST_DEVICE_NAME, TEST_DEVICE_TYPE, TEST_PUBLIC_KEY));
    }

    @Test
    @DisplayName("Should fail when getting non-existent device")
    void shouldFailForNonExistentDevice() {
        when(deviceRepository.findByUserIdAndDeviceId(TEST_USER_ID, TEST_DEVICE_ID))
                .thenReturn(Optional.empty());

        assertThrows(SecurityException.class, () ->
                deviceService.getDevice(TEST_USER_ID, TEST_DEVICE_ID));
    }

    private Device createDevice(String deviceId, boolean authorized, boolean revoked) {
        Device device = new Device();
        device.setId(1L);
        device.setUserId(TEST_USER_ID);
        device.setDeviceId(deviceId);
        device.setDeviceName(TEST_DEVICE_NAME);
        device.setDeviceType(TEST_DEVICE_TYPE);
        device.setEd25519PublicKey(TEST_PUBLIC_KEY);
        device.setAuthorized(authorized);
        device.setRevoked(revoked);
        return device;
    }

    static class FakeRedisService extends RedisService {

        private final Map<String, Object> store = new ConcurrentHashMap<>();
        private final Map<String, Duration> ttls = new ConcurrentHashMap<>();

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
    }
}
