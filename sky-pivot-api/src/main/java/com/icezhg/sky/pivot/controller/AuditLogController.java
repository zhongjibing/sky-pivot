package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.AuditLogPageResponse;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import com.icezhg.sky.pivot.service.AuditLogService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/account")
public class AuditLogController {

    private static final Logger log = LoggerFactory.getLogger(AuditLogController.class);

    private final AuditLogService auditLogService;

    public AuditLogController(AuditLogService auditLogService) {
        this.auditLogService = auditLogService;
    }

    @GetMapping("/audit-log")
    public ResponseEntity<ApiResponse<AuditLogPageResponse>> listAuditLog(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String level,
            @RequestParam(required = false) String action) {

        if (size > 100) {
            size = 100;
        }

        Long userId = JwtAuthContext.getUserId();

        AuditLogPageResponse result = auditLogService.listByUser(userId, page, size, level, action);
        return ResponseEntity.ok(ApiResponse.success(result));
    }
}
