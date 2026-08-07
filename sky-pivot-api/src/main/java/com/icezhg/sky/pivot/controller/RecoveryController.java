package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.RecoveryChallengeRequest;
import com.icezhg.sky.pivot.dto.RecoveryChallengeResponse;
import com.icezhg.sky.pivot.dto.RecoveryCodeResetRequest;
import com.icezhg.sky.pivot.dto.RecoveryStartRequest;
import com.icezhg.sky.pivot.dto.RecoveryTokenResponse;
import com.icezhg.sky.pivot.opaque.annotation.AuditLog;
import com.icezhg.sky.pivot.opaque.annotation.RequireDeviceSignature;
import com.icezhg.sky.pivot.opaque.service.RecoveryService;
import com.icezhg.sky.pivot.opaque.service.SessionTokenService;
import com.icezhg.sky.pivot.security.JwtAuthContext;

import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class RecoveryController {

    private static final Logger log = LoggerFactory.getLogger(RecoveryController.class);

    private final RecoveryService recoveryService;
    private final SessionTokenService sessionTokenService;

    public RecoveryController(RecoveryService recoveryService, SessionTokenService sessionTokenService) {
        this.recoveryService = recoveryService;
        this.sessionTokenService = sessionTokenService;
    }

    @PostMapping("/api/auth/recovery/challenge")
    public ResponseEntity<ApiResponse<RecoveryChallengeResponse>> createChallenge(
            @Valid @RequestBody RecoveryChallengeRequest request) {

        try {
            RecoveryChallengeResponse response = recoveryService.createChallenge(request.credentialIdentifier());
            return ResponseEntity.ok(ApiResponse.success(response));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(ApiResponse.error(HttpStatus.FORBIDDEN.value(), e.getMessage()));
        }
    }

    @PostMapping("/api/auth/recovery/start")
    @AuditLog(action = "RECOVERY_CODE_USED", targetType = "RECOVERY", level = "CRITICAL")
    public ResponseEntity<ApiResponse<RecoveryTokenResponse>> startRecovery(
            @Valid @RequestBody RecoveryStartRequest request) {

        try {
            RecoveryTokenResponse response = recoveryService.startRecovery(
                    request.requestId(), request.authCode());
            return ResponseEntity.ok(ApiResponse.success(response));
        } catch (SecurityException e) {
            String msg = e.getMessage();
            HttpStatus status = msg != null && msg.contains("replay")
                    ? HttpStatus.FORBIDDEN : HttpStatus.UNAUTHORIZED;
            return ResponseEntity.status(status)
                    .body(ApiResponse.error(status.value(), msg));
        }
    }

    @GetMapping("/api/auth/recovery/vault")
    public ResponseEntity<ApiResponse<Map<String, String>>> getRecoveryVault(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(HttpStatus.UNAUTHORIZED.value(), "Missing recovery token"));
        }

        String token = authHeader.substring(7);

        try {
            Long userId = sessionTokenService.getUserIdFromRecoveryToken(token);
            String encryptedUrk = recoveryService.getEncryptedUrkRecovery(userId);
            return ResponseEntity.ok(ApiResponse.success(Map.of(
                    "encryptedUrkRecovery", encryptedUrk
            )));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired recovery token"));
        }
    }

    @PostMapping("/api/account/recovery-code/reset")
    @AuditLog(action = "RECOVERY_CODE_RESET", targetType = "RECOVERY", level = "CRITICAL")
    @RequireDeviceSignature
    public ResponseEntity<ApiResponse<Void>> resetRecoveryCode(
            @Valid @RequestBody RecoveryCodeResetRequest request) {

        Long userId = JwtAuthContext.getUserId();

        try {
            recoveryService.resetRecoveryCode(userId, request);
            return ResponseEntity.ok(ApiResponse.success());
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(ApiResponse.error(HttpStatus.FORBIDDEN.value(), e.getMessage()));
        }
    }
}
