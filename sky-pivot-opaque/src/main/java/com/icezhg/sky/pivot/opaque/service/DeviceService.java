package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import com.icezhg.sky.pivot.entity.Device;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.DeviceRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class DeviceService {

    private static final Logger log = LoggerFactory.getLogger(DeviceService.class);

    private final DeviceRepository deviceRepository;
    private final UserRepository userRepository;
    private final RedisService redisService;

    public DeviceService(DeviceRepository deviceRepository,
                         UserRepository userRepository,
                         RedisService redisService) {
        this.deviceRepository = deviceRepository;
        this.userRepository = userRepository;
        this.redisService = redisService;
    }

    @Transactional
    public Device activate(Long userId, String deviceId, String deviceName,
                           String deviceType, String ed25519PublicKey) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new SecurityException("User not found: " + userId));

        Optional<Device> existing = deviceRepository.findByUserIdAndDeviceId(userId, deviceId);
        Device device;
        if (existing.isPresent()) {
            device = existing.get();
            device.setDeviceName(deviceName);
            device.setDeviceType(deviceType);
            device.setEd25519PublicKey(ed25519PublicKey);
            log.info("Reactivating existing device {} for user {}", deviceId, userId);
        } else {
            device = new Device();
            device.setUserId(userId);
            device.setDeviceId(deviceId);
            device.setDeviceName(deviceName);
            device.setDeviceType(deviceType);
            device.setEd25519PublicKey(ed25519PublicKey);

            List<Device> allDevices = deviceRepository.findByUserId(userId);
            long authorizedCount = allDevices.stream()
                    .filter(d -> Boolean.TRUE.equals(d.getAuthorized()) && !Boolean.TRUE.equals(d.getRevoked()))
                    .count();
            if (authorizedCount == 0) {
                device.setAuthorized(true);
                log.info("First device {} auto-authorized for user {}", deviceId, userId);
            } else {
                device.setAuthorized(false);
                log.info("Device {} registered pending authorization for user {}", deviceId, userId);
            }
        }

        device.setRevoked(false);
        device.setRevokedAt(null);
        device.setLastSeen(LocalDateTime.now());

        return deviceRepository.save(device);
    }

    public void authorizeDevice(Long userId, String deviceId) {
        Device device = deviceRepository.findByUserIdAndDeviceId(userId, deviceId)
                .orElseThrow(() -> new SecurityException("Device not found: " + deviceId));
        device.setAuthorized(true);
        device.setLastSeen(LocalDateTime.now());
        deviceRepository.save(device);
        log.info("Device {} authorized for user {}", deviceId, userId);
    }

    public List<Device> listDevices(Long userId) {
        return deviceRepository.findByUserId(userId);
    }

    public Device getDevice(Long userId, String deviceId) {
        return deviceRepository.findByUserIdAndDeviceId(userId, deviceId)
                .orElseThrow(() -> new SecurityException("Device not found: " + deviceId));
    }

    @Transactional
    public void revoke(Long userId, String deviceIdToRevoke) {
        Device device = deviceRepository.findByUserIdAndDeviceId(userId, deviceIdToRevoke)
                .orElseThrow(() -> new SecurityException("Device not found: " + deviceIdToRevoke));

        if (Boolean.TRUE.equals(device.getRevoked())) {
            log.warn("Device {} already revoked for user {}", deviceIdToRevoke, userId);
            return;
        }

        device.setRevoked(true);
        device.setRevokedAt(LocalDateTime.now());
        device.setAuthorized(false);
        deviceRepository.save(device);

        String blacklistKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_BLACKLIST, userId.toString(), deviceIdToRevoke);
        redisService.set(blacklistKey, "revoked", Duration.ofHours(3));

        log.warn("Device {} revoked for user {} — AT blacklist activated", deviceIdToRevoke, userId);
    }

    public boolean isDeviceRevoked(Long userId, String deviceId) {
        String blacklistKey = RedisKeyPrefix.key(RedisKeyPrefix.DEVICE_BLACKLIST, userId.toString(), deviceId);
        return redisService.hasKey(blacklistKey);
    }

    public void updateLastSeen(Long userId, String deviceId) {
        deviceRepository.findByUserIdAndDeviceId(userId, deviceId)
                .ifPresent(device -> {
                    device.setLastSeen(LocalDateTime.now());
                    deviceRepository.save(device);
                });
    }

    public static String generateRequestId() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }
}
