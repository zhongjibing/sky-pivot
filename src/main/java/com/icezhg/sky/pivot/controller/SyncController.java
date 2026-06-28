package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.SyncCheckResponse;
import com.icezhg.sky.pivot.dto.SyncPullResponse;
import com.icezhg.sky.pivot.security.JwtService;
import com.icezhg.sky.pivot.service.SyncService;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sync")
public class SyncController {

    private final SyncService syncService;
    private final JwtService jwtService;

    public SyncController(SyncService syncService, JwtService jwtService) {
        this.syncService = syncService;
        this.jwtService = jwtService;
    }

    @GetMapping("/check")
    public ApiResponse<SyncCheckResponse> check(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        Long userId = jwtService.validateToken(extractToken(authHeader));
        SyncCheckResponse result = syncService.checkVersion(userId);
        return ApiResponse.success(result);
    }

    @GetMapping("/pull")
    public ApiResponse<SyncPullResponse> pull(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            @RequestParam(defaultValue = "0") long sinceVersion) {
        Long userId = jwtService.validateToken(extractToken(authHeader));
        SyncPullResponse result = syncService.pullChanges(userId, sinceVersion);
        return ApiResponse.success(result);
    }

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new RuntimeException("Missing or invalid Authorization header");
    }
}
