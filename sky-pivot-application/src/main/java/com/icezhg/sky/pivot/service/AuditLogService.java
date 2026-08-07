package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.AuditLogPageResponse;
import com.icezhg.sky.pivot.dto.AuditLogResponse;
import com.icezhg.sky.pivot.entity.AuditLog;
import com.icezhg.sky.pivot.repository.AuditLogRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuditLogService {

    private static final Logger log = LoggerFactory.getLogger(AuditLogService.class);

    private final AuditLogRepository auditLogRepository;

    public AuditLogService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    public AuditLogPageResponse listByUser(Long userId, int page, int size, String level, String action) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<AuditLog> result;

        if (level != null && !level.isBlank()) {
            result = auditLogRepository.findByUserIdAndLevel(userId, level, pageable);
        } else if (action != null && !action.isBlank()) {
            result = auditLogRepository.findByUserIdAndAction(userId, action, pageable);
        } else {
            result = auditLogRepository.findByUserId(userId, pageable);
        }

        List<AuditLogResponse> items = result.getContent().stream()
                .map(AuditLogResponse::from)
                .toList();

        log.debug("Listed audit logs for userId={}: page={}, size={}, total={}",
                userId, page, size, result.getTotalElements());

        return new AuditLogPageResponse(
                items,
                result.getNumber(),
                result.getSize(),
                result.getTotalElements(),
                result.getTotalPages()
        );
    }
}
