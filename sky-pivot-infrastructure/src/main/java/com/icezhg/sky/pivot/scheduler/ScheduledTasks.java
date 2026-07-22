package com.icezhg.sky.pivot.scheduler;

import com.icezhg.sky.pivot.config.properties.LoginHistoryProperties;
import com.icezhg.sky.pivot.config.properties.TrashProperties;
import com.icezhg.sky.pivot.repository.LoginHistoryRepository;
import com.icezhg.sky.pivot.repository.PasswordRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Component
public class ScheduledTasks {

    private static final Logger log = LoggerFactory.getLogger(ScheduledTasks.class);

    private final PasswordRepository passwordRepository;
    private final LoginHistoryRepository loginHistoryRepository;
    private final int trashRetentionDays;
    private final int loginHistoryRetentionMonths;

    public ScheduledTasks(PasswordRepository passwordRepository,
                          LoginHistoryRepository loginHistoryRepository,
                          TrashProperties trashProperties,
                          LoginHistoryProperties loginHistoryProperties) {
        this.passwordRepository = passwordRepository;
        this.loginHistoryRepository = loginHistoryRepository;
        this.trashRetentionDays = trashProperties.getRetentionDays();
        this.loginHistoryRetentionMonths = loginHistoryProperties.getRetentionMonths();
    }

    @Scheduled(cron = "0 0 2 * * ?")
    @Transactional
    public void cleanExpiredTrash() {
        LocalDateTime threshold = LocalDateTime.now().minusDays(trashRetentionDays);
        int deleted = passwordRepository.deleteByDeletedAtBefore(threshold);
        log.info("Cleaned {} expired trash entries", deleted);
    }

    @Scheduled(cron = "0 0 3 * * ?")
    @Transactional
    public void cleanOldLoginHistory() {
        LocalDateTime threshold = LocalDateTime.now().minusMonths(loginHistoryRetentionMonths);
        int deleted = loginHistoryRepository.deleteByLoginAtBefore(threshold);
        log.info("Cleaned {} old login history records", deleted);
    }
}
