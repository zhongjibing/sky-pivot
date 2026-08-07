package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.config.SyncWebSocketHandler;
import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.entity.Device;
import com.icezhg.sky.pivot.opaque.annotation.AuditLog;
import com.icezhg.sky.pivot.opaque.annotation.RequireDeviceSignature;
import com.icezhg.sky.pivot.opaque.dto.*;
import com.icezhg.sky.pivot.opaque.service.AccessTokenService;
import com.icezhg.sky.pivot.opaque.service.DeviceAuthorizationService;
import com.icezhg.sky.pivot.opaque.service.DeviceAuthorizationService.EmergencyAuthChallengeData;
import com.icezhg.sky.pivot.opaque.service.DeviceAuthorizationService.EmergencyAuthResult;
import com.icezhg.sky.pivot.opaque.service.DeviceService;
import com.icezhg.sky.pivot.opaque.service.SessionTokenService;
import com.icezhg.sky.pivot.service.DeviceAuthRequestedEvent;
import com.icezhg.sky.pivot.service.DeviceRevokedEvent;
import com.icezhg.sky.pivot.service.EmergencyAuthUsedEvent;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private static final Logger log = LoggerFactory.getLogger(DeviceController.class);

    private final DeviceService deviceService;
    private final DeviceAuthorizationService deviceAuthorizationService;
    private final SessionTokenService sessionTokenService;
    private final AccessTokenService accessTokenService;
    private final SyncWebSocketHandler syncWebSocketHandler;
    private final ApplicationEventPublisher eventPublisher;

    public DeviceController(DeviceService deviceService,
                            DeviceAuthorizationService deviceAuthorizationService,
                            SessionTokenService sessionTokenService,
                            AccessTokenService accessTokenService,
                            SyncWebSocketHandler syncWebSocketHandler,
                            ApplicationEventPublisher eventPublisher) {
        this.deviceService = deviceService;
        this.deviceAuthorizationService = deviceAuthorizationService;
        this.sessionTokenService = sessionTokenService;
        this.accessTokenService = accessTokenService;
        this.syncWebSocketHandler = syncWebSocketHandler;
        this.eventPublisher = eventPublisher;
    }

    @PostMapping("/activate")
    public ResponseEntity<ApiResponse<DeviceActivateResponse>> activate(
            @Valid @RequestBody DeviceActivateRequest request,
            HttpServletRequest servletRequest) {

        Long userId = authenticateWithSt(servletRequest);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("401", "Invalid or expired session token"));
        }

        Device device = deviceService.activate(userId,
                request.deviceId(), request.deviceName(),
                request.deviceType(), request.ed25519PublicKey());

        boolean isFirstDevice = Boolean.TRUE.equals(device.getAuthorized());

        log.info("Device activated: userId={}, deviceId={}, firstDevice={}",
                userId, device.getDeviceId(), isFirstDevice);

        return ResponseEntity.ok(ApiResponse.success(new DeviceActivateResponse(
                device.getDeviceId(),
                device.getDeviceName(),
                device.getDeviceType(),
                device.getAuthorized(),
                isFirstDevice,
                device.getLastSeen() != null ? device.getLastSeen().toString() : null
        )));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<DeviceListItem>>> list(
            HttpServletRequest servletRequest) {

        Long userId = authenticateWithAt(servletRequest);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("401", "Invalid or expired access token"));
        }

        List<Device> devices = deviceService.listDevices(userId);
        List<DeviceListItem> items = devices.stream()
                .map(d -> new DeviceListItem(
                        d.getDeviceId(),
                        d.getDeviceName(),
                        d.getDeviceType(),
                        d.getAuthorized(),
                        d.getRevoked(),
                        d.getLastSeen() != null ? d.getLastSeen().toString() : null,
                        d.getCreatedAt() != null ? d.getCreatedAt().toString() : null
                ))
                .collect(Collectors.toList());

        return ResponseEntity.ok(ApiResponse.success(items));
    }

    @DeleteMapping("/{deviceId}")
    @AuditLog(action = "DEVICE_REVOKED", targetType = "DEVICE", level = "CRITICAL")
    @RequireDeviceSignature
    public ResponseEntity<ApiResponse<Void>> revoke(
            @PathVariable String deviceId,
            HttpServletRequest servletRequest) {

        Long userId = authenticateWithAt(servletRequest);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("401", "Invalid or expired access token"));
        }

        Device device = deviceService.getDevice(userId, deviceId);
        String deviceName = device.getDeviceName() != null ? device.getDeviceName() : deviceId;

        deviceService.revoke(userId, deviceId);
        accessTokenService.revokeAllForDevice(userId, deviceId);

        syncWebSocketHandler.notifyChange(userId,
                Map.of("type", "FORCE_LOGOUT", "deviceId", deviceId, "reason", "device_revoked"));

        eventPublisher.publishEvent(new DeviceRevokedEvent(userId, deviceId, deviceName));

        log.warn("Device {} revoked for user {}", deviceId, userId);

        return ResponseEntity.ok(ApiResponse.success());
    }

    @PostMapping("/authorize/level2/init")
    public ResponseEntity<ApiResponse<Level2AuthInitResponse>> level2Init(
            @Valid @RequestBody Level2AuthInitRequest request,
            HttpServletRequest servletRequest) {

        Long userId = authenticateWithSt(servletRequest);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("401", "Invalid or expired session token"));
        }

        String requestId = deviceAuthorizationService.initLevel2Auth(
                userId, request.tempPublicKey(), request.fingerprint());
        String fingerprint = deviceAuthorizationService.getFingerprintForRequest(requestId);

        eventPublisher.publishEvent(new DeviceAuthRequestedEvent(
                userId, requestId, "New Device", fingerprint));

        return ResponseEntity.ok(ApiResponse.success(new Level2AuthInitResponse(
                requestId, fingerprint, LocalDateTime.now().plusMinutes(5).toString()
        )));
    }

    @GetMapping("/authorize/level2/{requestId}")
    public ResponseEntity<ApiResponse<Level2AuthInitResponse>> level2Status(
            @PathVariable String requestId,
            HttpServletRequest servletRequest) {

        authenticateWithAt(servletRequest);

        try {
            String fingerprint = deviceAuthorizationService.getFingerprintForRequest(requestId);
            return ResponseEntity.ok(ApiResponse.success(new Level2AuthInitResponse(
                    requestId, fingerprint, null
            )));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("404", e.getMessage()));
        }
    }

    @PostMapping("/authorize/level2/totp")
    @AuditLog(action = "DEVICE_AUTH_LEVEL2_TOTP", targetType = "DEVICE")
    @RequireDeviceSignature
    public ResponseEntity<ApiResponse<Void>> level2ConfirmTotp(
            @Valid @RequestBody Level2AuthConfirmRequest request,
            HttpServletRequest servletRequest) {

        authenticateWithAt(servletRequest);

        try {
            boolean valid = deviceAuthorizationService.verifyTotp(
                    request.requestId(), request.totpCode());
            if (!valid) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(ApiResponse.error("403", "Invalid TOTP code"));
            }
            return ResponseEntity.ok(ApiResponse.success());
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("404", e.getMessage()));
        }
    }

    @PostMapping("/authorize/level2/upload-dek")
    @AuditLog(action = "DEVICE_AUTH_LEVEL2_DEK", targetType = "DEVICE")
    @RequireDeviceSignature
    public ResponseEntity<ApiResponse<Void>> level2UploadDek(
            @Valid @RequestBody Level2AuthCompleteRequest request,
            HttpServletRequest servletRequest) {

        authenticateWithAt(servletRequest);

        String encryptedDek = request.encryptedDek();
        if (encryptedDek != null && !encryptedDek.isBlank()) {
            deviceAuthorizationService.storeEncryptedDek(
                    request.requestId(), encryptedDek);
        }

        return ResponseEntity.ok(ApiResponse.success());
    }

    @PostMapping("/authorize/level2/complete")
    @AuditLog(action = "DEVICE_AUTH_LEVEL2_COMPLETE", targetType = "DEVICE")
    public ResponseEntity<ApiResponse<DeviceActivateResponse>> level2Complete(
            @Valid @RequestBody Level2AuthCompleteRequest request,
            HttpServletRequest servletRequest) {

        Long userId = authenticateWithSt(servletRequest);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("401", "Invalid or expired session token"));
        }

        try {
            String dekData = deviceAuthorizationService.getEncryptedDek(request.requestId());

            Device device = deviceService.activate(userId,
                    request.deviceId(), request.deviceName(),
                    request.deviceType(), request.ed25519PublicKey());
            deviceService.authorizeDevice(userId, request.deviceId());

            log.info("Level 2 device authorization completed: userId={}, deviceId={}",
                    userId, request.deviceId());

            return ResponseEntity.ok(ApiResponse.success(new DeviceActivateResponse(
                    device.getDeviceId(),
                    device.getDeviceName(),
                    device.getDeviceType(),
                    device.getAuthorized(),
                    false,
                    device.getLastSeen() != null ? device.getLastSeen().toString() : null
            )));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("404", e.getMessage()));
        }
    }

    @GetMapping("/authorize/level2/{requestId}/dek")
    public ResponseEntity<ApiResponse<Map<String, String>>> level2DownloadDek(
            @PathVariable String requestId,
            HttpServletRequest servletRequest) {

        authenticateWithSt(servletRequest);

        try {
            String encryptedDek = deviceAuthorizationService.getEncryptedDek(requestId);
            return ResponseEntity.ok(ApiResponse.success(Map.of("encryptedDek", encryptedDek)));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("404", e.getMessage()));
        }
    }

    @PostMapping("/emergency-auth/challenge")
    public ResponseEntity<ApiResponse<EmergencyAuthChallengeResponse>> emergencyAuthChallenge(
            @Valid @RequestBody EmergencyAuthChallengeRequest request) {

        try {
            EmergencyAuthChallengeData data = deviceAuthorizationService.initEmergencyAuth(
                    request.credentialIdentifier());

            return ResponseEntity.ok(ApiResponse.success(new EmergencyAuthChallengeResponse(
                    data.requestId(),
                    data.recoverySalt(),
                    data.challenge(),
                    data.expiresAt()
            )));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("404", e.getMessage()));
        }
    }

    @PostMapping("/emergency-auth/verify")
    @AuditLog(action = "EMERGENCY_AUTH", targetType = "DEVICE", level = "CRITICAL")
    public ResponseEntity<ApiResponse<EmergencyAuthResponse>> emergencyAuthVerify(
            @Valid @RequestBody EmergencyAuthVerifyRequest request,
            HttpServletRequest servletRequest) {

        try {
            EmergencyAuthResult result = deviceAuthorizationService.verifyEmergencyAuth(
                    request.requestId(),
                    request.recoveryKeyHash(),
                    request.smsCode(),
                    request.deviceId(),
                    request.deviceName(),
                    request.deviceType(),
                    request.ed25519PublicKey()
            );

            log.warn("EMERGENCY_AUTH verified: deviceId={}", request.deviceId());

            try {
                Long emergencyUserId = deviceAuthorizationService.getUserIdForRequest(request.requestId());
                eventPublisher.publishEvent(new EmergencyAuthUsedEvent(
                        emergencyUserId, result.deviceId(), request.deviceName()));
            } catch (Exception e) {
                log.warn("Could not publish EmergencyAuthUsedEvent: {}", e.getMessage());
            }

            return ResponseEntity.ok(ApiResponse.success(new EmergencyAuthResponse(
                    result.deviceId(),
                    result.authorized(),
                    result.emergencyMode(),
                    result.expiresAt(),
                    result.requiresNewRecoveryCode()
            )));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(ApiResponse.error("403", e.getMessage()));
        }
    }

    private Long authenticateWithSt(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        String token = authHeader.substring(7);
        try {
            Claims claims = sessionTokenService.verifySessionToken(token);
            return Long.parseLong(claims.getSubject());
        } catch (Exception e) {
            log.debug("ST authentication failed: {}", e.getMessage());
            return null;
        }
    }

    private Long authenticateWithAt(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        String token = authHeader.substring(7);
        try {
            return accessTokenService.getUserIdFromAt(token);
        } catch (Exception e) {
            log.debug("AT authentication failed: {}", e.getMessage());
            return null;
        }
    }

}
