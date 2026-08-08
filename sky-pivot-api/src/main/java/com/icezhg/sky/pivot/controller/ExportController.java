package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.VaultExportRequest;
import com.icezhg.sky.pivot.dto.VaultExportResponse;
import com.icezhg.sky.pivot.opaque.annotation.RequireDeviceSignature;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import com.icezhg.sky.pivot.service.VaultExportService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/account")
public class ExportController {

    private static final Logger log = LoggerFactory.getLogger(ExportController.class);

    private final VaultExportService vaultExportService;

    public ExportController(VaultExportService vaultExportService) {
        this.vaultExportService = vaultExportService;
    }

    @PostMapping("/export")
    @RequireDeviceSignature
    @com.icezhg.sky.pivot.opaque.annotation.AuditLog(action = "VAULT_EXPORT", targetType = "VAULT", level = "CRITICAL")
    public ResponseEntity<ApiResponse<VaultExportResponse>> exportVault(
            @RequestBody VaultExportRequest request) {

        Long userId = JwtAuthContext.getUserId();
        String deviceId = JwtAuthContext.getDeviceId();

        log.warn("VAULT_EXPORT initiated: userId={}, deviceId={}", userId, deviceId);

        VaultExportResponse exportData = vaultExportService.assembleExportData(userId);

        log.warn("VAULT_EXPORT completed: userId={}, deviceId={}, itemCount={}",
                userId, deviceId, exportData.items().size());

        return ResponseEntity.ok(ApiResponse.success(exportData));
    }
}
