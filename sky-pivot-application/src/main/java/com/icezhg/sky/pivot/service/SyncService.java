package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.SyncEntry;
import com.icezhg.sky.pivot.dto.SyncLogEntry;
import com.icezhg.sky.pivot.dto.SyncPullResponse;
import com.icezhg.sky.pivot.dto.SyncPushRequest;
import com.icezhg.sky.pivot.dto.SyncPushResponse;
import com.icezhg.sky.pivot.entity.SyncLog;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.security.DeviceSignatureService;
import com.icezhg.sky.pivot.repository.SyncLogRepository;
import com.icezhg.sky.pivot.repository.UserRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class SyncService {

    private static final Logger log = LoggerFactory.getLogger(SyncService.class);
    static final String SERVER_GENERATED_SIGNATURE = "SERVER_DIRECT";

    private final SyncLogRepository syncLogRepository;
    private final UserRepository userRepository;
    private final DeviceSignatureService deviceSignatureService;
    private final ApplicationEventPublisher eventPublisher;

    public SyncService(SyncLogRepository syncLogRepository,
                       UserRepository userRepository,
                       DeviceSignatureService deviceSignatureService,
                       ApplicationEventPublisher eventPublisher) {
        this.syncLogRepository = syncLogRepository;
        this.userRepository = userRepository;
        this.deviceSignatureService = deviceSignatureService;
        this.eventPublisher = eventPublisher;
    }

    @Transactional
    public SyncPushResponse pushSync(Long userId, String deviceId, SyncPushRequest request) {
        long now = System.currentTimeMillis();
        List<SyncLog> entries = new ArrayList<>();

        for (SyncEntry entry : request.entries()) {
            deviceSignatureService.verifyContentSignature(
                    userId, deviceId, entry.signedContentBytes(), entry.deviceSignature());

            SyncLog syncLog = new SyncLog();
            syncLog.setServerTimestamp(now);
            syncLog.setUserId(userId);
            syncLog.setDeviceId(deviceId);
            syncLog.setOpId(entry.opId());
            syncLog.setOperation(entry.operation());
            syncLog.setTargetType(entry.targetType());
            syncLog.setTargetId(entry.targetId());
            syncLog.setTargetVersion(entry.targetVersion());
            syncLog.setClientTimestamp(entry.clientTimestamp());
            syncLog.setLamportClock(entry.lamportClock());
            syncLog.setDeviceSignature(entry.deviceSignature());
            entries.add(syncLog);
        }

        syncLogRepository.saveAll(entries);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalStateException("User not found: " + userId));
        long currentVersion = user.getSyncVersion();

        publishSyncEvent(userId, currentVersion, entries);

        log.info("Sync push accepted {} entries for user {}", entries.size(), userId);
        return new SyncPushResponse(entries.size(), currentVersion);
    }

    public SyncPullResponse pullSync(Long userId, long sinceVersion) {
        List<SyncLog> logs = syncLogRepository.findByUserIdAndTargetVersionGreaterThan(userId, sinceVersion);

        List<SyncLogEntry> entries = logs.stream()
                .map(this::toSyncLogEntry)
                .toList();

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalStateException("User not found: " + userId));

        return new SyncPullResponse(entries, user.getSyncVersion());
    }

    public long getSyncVersion(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalStateException("User not found: " + userId));
        return user.getSyncVersion();
    }

    public void recordOperation(Long userId, String deviceId, String operation,
                                 String targetId, String targetType, long targetVersion) {
        long now = System.currentTimeMillis();
        String effectiveDeviceId = deviceId != null ? deviceId : "SERVER";

        SyncLog syncLog = new SyncLog();
        syncLog.setServerTimestamp(now);
        syncLog.setUserId(userId);
        syncLog.setDeviceId(effectiveDeviceId);
        syncLog.setOpId(UUID.randomUUID().toString());
        syncLog.setOperation(operation);
        syncLog.setTargetType(targetType != null ? targetType : "VAULT_ITEM");
        syncLog.setTargetId(targetId);
        syncLog.setTargetVersion(targetVersion);
        syncLog.setClientTimestamp(now);
        syncLog.setLamportClock(targetVersion);
        syncLog.setDeviceSignature(SERVER_GENERATED_SIGNATURE);

        syncLogRepository.save(syncLog);

        log.debug("Recorded sync log: userId={}, operation={}, targetId={}, version={}",
                userId, operation, targetId, targetVersion);

        publishSyncEvent(userId, targetVersion, List.of(syncLog));
    }

    public int archiveEntriesBefore(long beforeTimestamp) {
        int archived = syncLogRepository.archiveByServerTimestampBefore(beforeTimestamp);
        if (archived > 0) {
            int deleted = syncLogRepository.deleteByServerTimestampBefore(beforeTimestamp);
            log.info("Archived {} sync_log entries, deleted {} entries", archived, deleted);
        }
        return archived;
    }

    private SyncLogEntry toSyncLogEntry(SyncLog s) {
        return new SyncLogEntry(
                s.getOpId(),
                s.getDeviceId(),
                s.getOperation(),
                s.getTargetType(),
                s.getTargetId(),
                s.getTargetVersion(),
                s.getClientTimestamp(),
                s.getServerTimestamp(),
                s.getLamportClock()
        );
    }

    private void publishSyncEvent(Long userId, long newVersion, List<SyncLog> entries) {
        List<SyncLogEntry> changedEntries = entries.stream()
                .map(this::toSyncLogEntry)
                .toList();
        eventPublisher.publishEvent(new SyncEvent(userId, newVersion, changedEntries));
    }
}
