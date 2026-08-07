package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.SyncCheckResponse;
import com.icezhg.sky.pivot.dto.SyncPullResponse;
import com.icezhg.sky.pivot.dto.SyncPushRequest;
import com.icezhg.sky.pivot.dto.SyncPushResponse;
import com.icezhg.sky.pivot.opaque.annotation.RequireDeviceSignature;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import com.icezhg.sky.pivot.service.SyncService;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sync")
public class SyncController {

    private static final Logger log = LoggerFactory.getLogger(SyncController.class);

    private final SyncService syncService;

    public SyncController(SyncService syncService) {
        this.syncService = syncService;
    }

    @PostMapping("/push")
    @RequireDeviceSignature
    public ResponseEntity<ApiResponse<SyncPushResponse>> push(
            @Valid @RequestBody SyncPushRequest request) {

        Long userId = JwtAuthContext.getUserId();
        String deviceId = JwtAuthContext.getDeviceId();

        SyncPushResponse result = syncService.pushSync(userId, deviceId, request);
        return ResponseEntity.ok(ApiResponse.success(result));
    }

    @GetMapping("/pull")
    public ResponseEntity<ApiResponse<SyncPullResponse>> pull(
            @RequestParam(defaultValue = "0") long sinceVersion) {

        Long userId = JwtAuthContext.getUserId();

        SyncPullResponse result = syncService.pullSync(userId, sinceVersion);
        return ResponseEntity.ok(ApiResponse.success(result));
    }

    @GetMapping("/check")
    public ResponseEntity<ApiResponse<SyncCheckResponse>> check() {

        Long userId = JwtAuthContext.getUserId();

        long version = syncService.getSyncVersion(userId);
        return ResponseEntity.ok(ApiResponse.success(new SyncCheckResponse(version)));
    }
}
