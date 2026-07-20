package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.SyncCheckResponse;
import com.icezhg.sky.pivot.dto.SyncPullResponse;
import com.icezhg.sky.pivot.service.SyncService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sync")
public class SyncController {

    private final SyncService syncService;

    public SyncController(SyncService syncService) {
        this.syncService = syncService;
    }

    @GetMapping("/check")
    public ApiResponse<SyncCheckResponse> check() {
        SyncCheckResponse result = syncService.checkVersion();
        return ApiResponse.success(result);
    }

    @GetMapping("/pull")
    public ApiResponse<SyncPullResponse> pull(
            @RequestParam(defaultValue = "0") long sinceVersion) {
        SyncPullResponse result = syncService.pullChanges(sinceVersion);
        return ApiResponse.success(result);
    }
}
