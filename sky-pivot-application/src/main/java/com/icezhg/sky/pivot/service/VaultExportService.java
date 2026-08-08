package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.BackupStatusResponse;
import com.icezhg.sky.pivot.dto.ExportDeviceInfo;
import com.icezhg.sky.pivot.dto.VaultExportResponse;
import com.icezhg.sky.pivot.dto.VaultItemResponse;
import com.icezhg.sky.pivot.entity.Device;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.entity.VaultItem;
import com.icezhg.sky.pivot.repository.DeviceRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import com.icezhg.sky.pivot.repository.VaultItemRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class VaultExportService {

    private static final Logger log = LoggerFactory.getLogger(VaultExportService.class);

    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final VaultItemRepository vaultItemRepository;

    public VaultExportService(UserRepository userRepository,
                               DeviceRepository deviceRepository,
                               VaultItemRepository vaultItemRepository) {
        this.userRepository = userRepository;
        this.deviceRepository = deviceRepository;
        this.vaultItemRepository = vaultItemRepository;
    }

    @Transactional(readOnly = true)
    public VaultExportResponse assembleExportData(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        List<Device> devices = deviceRepository.findByUserId(userId);
        List<ExportDeviceInfo> deviceInfos = devices.stream()
                .filter(d -> d.getAuthorized() && !d.getRevoked())
                .map(d -> new ExportDeviceInfo(d.getDeviceId(), d.getEd25519PublicKey()))
                .toList();

        List<VaultItem> items = vaultItemRepository.findByUserIdAndDeletedAtIsNull(userId);
        List<VaultItemResponse> itemResponses = items.stream()
                .map(this::toResponse)
                .toList();

        log.info("Assembled export data for userId={}: {} devices, {} items",
                userId, deviceInfos.size(), itemResponses.size());

        return new VaultExportResponse(
                user.getSalt(),
                user.getEncryptedDek(),
                user.getEncryptedUrkRecovery(),
                user.getRecoverySalt(),
                user.getRecoveryKeyHash(),
                user.getSyncVersion(),
                deviceInfos,
                itemResponses
        );
    }

    public BackupStatusResponse getBackupStatus(LocalDateTime lastBackupAt, long lastBackupSize,
                                                  int totalBackups, LocalDateTime nextScheduledAt) {
        return new BackupStatusResponse(
                lastBackupAt != null ? "COMPLETED" : "NEVER_RUN",
                lastBackupAt,
                lastBackupSize,
                totalBackups,
                nextScheduledAt
        );
    }

    private VaultItemResponse toResponse(VaultItem item) {
        return new VaultItemResponse(
                item.getId(),
                item.getItemId(),
                item.getEncryptedBlob(),
                item.getVersion(),
                item.getCreatedAt(),
                item.getUpdatedAt()
        );
    }
}
