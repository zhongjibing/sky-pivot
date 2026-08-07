package com.icezhg.sky.pivot.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class SyncLogArchivalScheduler {

    private static final Logger log = LoggerFactory.getLogger(SyncLogArchivalScheduler.class);

    private static final long NINETY_DAYS_MS = 90L * 24 * 60 * 60 * 1000;

    private final SyncService syncService;

    public SyncLogArchivalScheduler(SyncService syncService) {
        this.syncService = syncService;
    }

    @Scheduled(cron = "0 0 3 * * ?")
    public void archiveOldSyncLogs() {
        long cutoffTimestamp = System.currentTimeMillis() - NINETY_DAYS_MS;
        try {
            int archived = syncService.archiveEntriesBefore(cutoffTimestamp);
            log.info("Sync log archival completed: {} entries archived", archived);
        } catch (Exception e) {
            log.error("Sync log archival failed", e);
        }
    }
}
