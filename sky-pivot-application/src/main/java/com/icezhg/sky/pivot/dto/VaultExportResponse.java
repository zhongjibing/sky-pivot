package com.icezhg.sky.pivot.dto;

import java.util.List;

public record VaultExportResponse(
        String salt,
        String encryptedDek,
        String encryptedUrkRecovery,
        String recoverySalt,
        String recoveryKeyHash,
        long syncVersion,
        List<ExportDeviceInfo> devices,
        List<VaultItemResponse> items
) {}
