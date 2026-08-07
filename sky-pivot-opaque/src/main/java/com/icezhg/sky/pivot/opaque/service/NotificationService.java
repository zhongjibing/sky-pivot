package com.icezhg.sky.pivot.opaque.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    public void sendAccountLockedNotification(Long userId, long lockDurationMinutes) {
        log.warn("NOTIFICATION: Account locked for userId={}, duration={} minutes. "
                + "Send email/SMS notification (mock).", userId, lockDurationMinutes);
    }
}
