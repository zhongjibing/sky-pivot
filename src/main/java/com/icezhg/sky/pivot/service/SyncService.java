package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.SyncCheckResponse;
import com.icezhg.sky.pivot.dto.SyncPullResponse;
import com.icezhg.sky.pivot.entity.Password;
import com.icezhg.sky.pivot.entity.SyncVersion;
import com.icezhg.sky.pivot.repository.PasswordRepository;
import com.icezhg.sky.pivot.repository.SyncVersionRepository;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;

@Service
public class SyncService {

    private final SyncVersionRepository syncVersionRepository;
    private final PasswordRepository passwordRepository;

    public SyncService(SyncVersionRepository syncVersionRepository,
                       PasswordRepository passwordRepository) {
        this.syncVersionRepository = syncVersionRepository;
        this.passwordRepository = passwordRepository;
    }

    public SyncCheckResponse checkVersion() {
        Long userId = JwtAuthContext.getUserId();
        SyncVersion syncVersion = syncVersionRepository.findByUserId(userId)
            .orElseGet(() -> {
                SyncVersion sv = new SyncVersion();
                sv.setUserId(userId);
                sv.setVersion(0L);
                return syncVersionRepository.save(sv);
            });
        return new SyncCheckResponse(syncVersion.getVersion());
    }

    public SyncPullResponse pullChanges(long sinceVersion) {
        Long userId = JwtAuthContext.getUserId();
        SyncVersion syncVersion = syncVersionRepository.findByUserId(userId).orElse(null);
        if (syncVersion == null || syncVersion.getVersion() <= sinceVersion) {
            return new SyncPullResponse(List.of());
        }

        LocalDateTime since = LocalDateTime.ofInstant(
            Instant.ofEpochMilli(sinceVersion), ZoneOffset.UTC
        );

        List<Password> changes = passwordRepository.findByUserIdAndUpdatedAtAfter(userId, since);

        List<SyncPullResponse.SyncChange> changeList = changes.stream()
            .map(p -> new SyncPullResponse.SyncChange(
                p.isDeleted() ? "DELETE" : "UPSERT",
                p.getId(),
                p.getTitle(),
                p.getAccount(),
                p.getUrl(),
                p.getHealthLevel(),
                p.getUpdatedAt(),
                p.getDeletedAt()
            ))
            .toList();

        syncVersionRepository.save(syncVersion);

        return new SyncPullResponse(changeList);
    }
}
