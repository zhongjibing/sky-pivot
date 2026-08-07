package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.entity.AuditLog;
import com.icezhg.sky.pivot.repository.AuditLogRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class LoginAuditService {

    private static final Logger log = LoggerFactory.getLogger(LoginAuditService.class);

    private final AuditLogRepository auditLogRepository;

    public LoginAuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public void recordLoginSuccess(Long userId, String ipAddress, String userAgent, String requestId) {
        try {
            AuditLog entry = new AuditLog();
            entry.setUserId(userId);
            entry.setAction("LOGIN_SUCCESS");
            entry.setLevel("INFO");
            entry.setResult("SUCCESS");
            entry.setIpAddress(ipAddress);
            entry.setUserAgent(userAgent);
            entry.setRequestId(requestId);
            entry.setCreatedAt(LocalDateTime.now());
            auditLogRepository.save(entry);
        } catch (Exception e) {
            log.warn("Failed to write login success audit log: {}", e.getMessage());
        }
    }

    public void recordLoginFailure(Long userId, String ipAddress, String userAgent,
                                     String requestId, String reason) {
        try {
            AuditLog entry = new AuditLog();
            entry.setUserId(userId);
            entry.setAction("LOGIN_FAILURE");
            entry.setLevel("WARNING");
            entry.setResult("FAILURE");
            entry.setReason(reason);
            entry.setIpAddress(ipAddress);
            entry.setUserAgent(userAgent);
            entry.setRequestId(requestId);
            entry.setCreatedAt(LocalDateTime.now());
            auditLogRepository.save(entry);
        } catch (Exception e) {
            log.warn("Failed to write login failure audit log: {}", e.getMessage());
        }
    }

    public void recordAccountLocked(Long userId, String ipAddress, String reason) {
        try {
            AuditLog entry = new AuditLog();
            entry.setUserId(userId);
            entry.setAction("ACCOUNT_LOCKED");
            entry.setLevel("CRITICAL");
            entry.setResult("LOCKED");
            entry.setReason(reason);
            entry.setIpAddress(ipAddress);
            entry.setCreatedAt(LocalDateTime.now());
            auditLogRepository.save(entry);
        } catch (Exception e) {
            log.warn("Failed to write account locked audit log: {}", e.getMessage());
        }
    }
}
