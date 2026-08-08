package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.config.properties.BackupProperties;
import com.icezhg.sky.pivot.config.vault.VaultSecretKeys;
import com.icezhg.sky.pivot.config.vault.VaultSecretService;
import com.icezhg.sky.pivot.dto.BackupStatusResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

@Service
public class BackupService {

    private static final Logger log = LoggerFactory.getLogger(BackupService.class);
    private static final DateTimeFormatter FILE_DATE = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private final BackupProperties backupProperties;
    private final VaultSecretService vaultSecretService;
    private final ReentrantLock backupLock = new ReentrantLock();

    private volatile LocalDateTime lastBackupAt;
    private volatile long lastBackupSize;
    private volatile int totalBackups;

    public BackupService(BackupProperties backupProperties, VaultSecretService vaultSecretService) {
        this.backupProperties = backupProperties;
        this.vaultSecretService = vaultSecretService;
    }

    public BackupResult performScheduledBackup() {
        if (!backupProperties.isEnabled()) {
            log.debug("Backup is disabled, skipping scheduled backup");
            return new BackupResult(false, 0, "Backup is disabled");
        }
        boolean success = runBackup();
        return new BackupResult(success, lastBackupSize,
                success ? null : "Backup process returned non-zero exit code");
    }

    public record BackupResult(boolean success, long fileSize, String errorMessage) {}

    public BackupStatusResponse getStatus() {
        LocalDateTime nextScheduled = lastBackupAt != null
                ? lastBackupAt.plusDays(1).withHour(2).withMinute(0).withSecond(0)
                : LocalDateTime.now().plusDays(1).withHour(2).withMinute(0).withSecond(0);

        return new BackupStatusResponse(
                lastBackupAt != null ? "COMPLETED" : "NEVER_RUN",
                lastBackupAt,
                lastBackupSize,
                totalBackups,
                nextScheduled
        );
    }

    public boolean runBackup() {
        if (!backupLock.tryLock()) {
            log.warn("Backup already in progress, skipping");
            return false;
        }

        try {
            Path backupDir = Path.of(backupProperties.getDirectory());
            Files.createDirectories(backupDir);

            String timestamp = FILE_DATE.format(LocalDateTime.now());
            String fileName = "sky_pivot_backup_" + timestamp + ".sql.gz";
            Path backupFile = backupDir.resolve(fileName);

            String backupKey = null;
            try {
                backupKey = vaultSecretService.readSecret(backupProperties.getEncryptionKeyVaultPath());
                log.info("Loaded backup encryption key from Vault");
            } catch (Exception e) {
                log.warn("Could not load backup encryption key from Vault: {}", e.getMessage());
            }

            ProcessBuilder pb = buildMysqldumpCommand(backupFile);
            Process process = pb.start();

            StringBuilder errorOutput = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    errorOutput.append(line).append('\n');
                }
            }

            boolean completed = process.waitFor(300, TimeUnit.SECONDS);
            int exitCode = process.exitValue();

            if (completed && exitCode == 0) {
                long fileSize = Files.size(backupFile);
                lastBackupAt = LocalDateTime.now();
                lastBackupSize = fileSize;
                totalBackups++;

                log.info("Backup completed: file={}, size={} bytes, exitCode={}", fileName, fileSize, exitCode);

                if (backupKey != null) {
                    log.info("Backup encryption key available — encryption should be applied at storage level");
                }

                cleanupOldBackups(backupDir);
                return true;
            } else {
                log.error("Backup failed: exitCode={}, stderr={}", exitCode, errorOutput.toString().trim());
                return false;
            }
        } catch (Exception e) {
            log.error("Backup execution failed", e);
            return false;
        } finally {
            backupLock.unlock();
        }
    }

    private ProcessBuilder buildMysqldumpCommand(Path outputFile) {
        return new ProcessBuilder(
                backupProperties.getMysqldumpPath(),
                "--single-transaction",
                "--routines",
                "--triggers",
                "--events",
                "--set-gtid-purged=OFF",
                "-h", extractHost(),
                "-P", extractPort(),
                "-u", backupProperties.getDatabaseUser(),
                backupProperties.getDatabaseName()
        )
                .redirectOutput(outputFile.toFile())
                .redirectError(ProcessBuilder.Redirect.PIPE);
    }

    private String extractHost() {
        String url = backupProperties.getDatabaseUrl();
        String hostPort = url.replaceAll(".*://", "").split("/")[0];
        return hostPort.contains(":") ? hostPort.split(":")[0] : hostPort;
    }

    private String extractPort() {
        String url = backupProperties.getDatabaseUrl();
        String hostPort = url.replaceAll(".*://", "").split("/")[0];
        return hostPort.contains(":") ? hostPort.split(":")[1] : "3306";
    }

    private void cleanupOldBackups(Path backupDir) {
        if (backupProperties.getRetentionDays() <= 0) {
            return;
        }
        try {
            LocalDateTime cutoff = LocalDateTime.now().minusDays(backupProperties.getRetentionDays());
            Files.list(backupDir)
                    .filter(p -> p.getFileName().toString().startsWith("sky_pivot_backup_"))
                    .filter(p -> {
                        try {
                            return Files.getLastModifiedTime(p).toInstant()
                                    .isBefore(cutoff.toInstant(java.time.ZoneOffset.UTC));
                        } catch (Exception e) {
                            return false;
                        }
                    })
                    .forEach(p -> {
                        try {
                            Files.delete(p);
                            log.info("Deleted old backup: {}", p.getFileName());
                        } catch (Exception e) {
                            log.warn("Failed to delete old backup: {}", p.getFileName(), e);
                        }
                    });
        } catch (Exception e) {
            log.warn("Failed to cleanup old backups", e);
        }
    }
}
