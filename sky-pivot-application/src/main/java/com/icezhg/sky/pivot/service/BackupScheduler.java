package com.icezhg.sky.pivot.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class BackupScheduler {

    private static final Logger log = LoggerFactory.getLogger(BackupScheduler.class);

    private final BackupService backupService;

    public BackupScheduler(BackupService backupService) {
        this.backupService = backupService;
    }

    @Scheduled(cron = "0 30 2 * * ?")
    public void performDatabaseBackup() {
        log.info("Starting scheduled database backup");
        BackupService.BackupResult result = backupService.performScheduledBackup();
        if (result.success()) {
            log.info("Scheduled database backup completed: size={} bytes", result.fileSize());
        } else {
            log.error("Scheduled database backup failed: {}", result.errorMessage());
        }
    }
}
