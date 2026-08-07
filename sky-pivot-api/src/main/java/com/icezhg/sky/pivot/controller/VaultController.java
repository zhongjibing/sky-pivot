package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.VaultItemCreateRequest;
import com.icezhg.sky.pivot.dto.VaultItemResponse;
import com.icezhg.sky.pivot.dto.VaultItemUpdateRequest;
import com.icezhg.sky.pivot.dto.VaultListResponse;
import com.icezhg.sky.pivot.dto.VaultTrashItemResponse;
import com.icezhg.sky.pivot.exception.VaultException;
import com.icezhg.sky.pivot.opaque.annotation.AuditLog;
import com.icezhg.sky.pivot.opaque.annotation.RequireDeviceSignature;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import com.icezhg.sky.pivot.service.VaultService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/vault")
public class VaultController {

    private static final Logger log = LoggerFactory.getLogger(VaultController.class);

    private final VaultService vaultService;

    public VaultController(VaultService vaultService) {
        this.vaultService = vaultService;
    }

    @PostMapping("/items")
    @AuditLog(action = "VAULT_ITEM_CREATE", targetType = "VAULT_ITEM")
    @RequireDeviceSignature
    public ResponseEntity<ApiResponse<VaultItemResponse>> create(
            @Valid @RequestBody VaultItemCreateRequest request) {

        Long userId = JwtAuthContext.getUserId();
        String deviceId = JwtAuthContext.getDeviceId();

        try {
            VaultItemResponse result = vaultService.create(userId, deviceId, request);
            return ResponseEntity.ok(ApiResponse.success(result));
        } catch (VaultException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiResponse.error(HttpStatus.CONFLICT.value(), e.getMessage()));
        }
    }

    @GetMapping("/items/{itemId}")
    public ResponseEntity<ApiResponse<VaultItemResponse>> get(
            @PathVariable String itemId) {

        Long userId = JwtAuthContext.getUserId();

        try {
            VaultItemResponse result = vaultService.get(userId, itemId);
            return ResponseEntity.ok(ApiResponse.success(result));
        } catch (VaultException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error(HttpStatus.NOT_FOUND.value(), e.getMessage()));
        }
    }

    @GetMapping
    public ResponseEntity<ApiResponse<VaultListResponse>> list(
            @RequestParam(required = false) Long sinceVersion) {

        Long userId = JwtAuthContext.getUserId();
        VaultListResponse result = vaultService.list(userId, sinceVersion);
        return ResponseEntity.ok(ApiResponse.success(result));
    }

    @PutMapping("/items/{itemId}")
    @AuditLog(action = "VAULT_ITEM_UPDATE", targetType = "VAULT_ITEM")
    @RequireDeviceSignature
    public ResponseEntity<ApiResponse<VaultItemResponse>> update(
            @PathVariable String itemId,
            @Valid @RequestBody VaultItemUpdateRequest request) {

        Long userId = JwtAuthContext.getUserId();
        String deviceId = JwtAuthContext.getDeviceId();

        try {
            VaultItemResponse result = vaultService.update(userId, deviceId, itemId, request);
            return ResponseEntity.ok(ApiResponse.success(result));
        } catch (VaultException e) {
            if (e.getMessage().contains("Version conflict")) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(ApiResponse.error(HttpStatus.CONFLICT.value(), e.getMessage()));
            }
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error(HttpStatus.NOT_FOUND.value(), e.getMessage()));
        }
    }

    @DeleteMapping("/items/{itemId}")
    @AuditLog(action = "VAULT_ITEM_DELETE", targetType = "VAULT_ITEM")
    @RequireDeviceSignature
    public ResponseEntity<ApiResponse<Void>> delete(
            @PathVariable String itemId) {

        Long userId = JwtAuthContext.getUserId();
        String deviceId = JwtAuthContext.getDeviceId();

        try {
            vaultService.delete(userId, deviceId, itemId);
            return ResponseEntity.ok(ApiResponse.success());
        } catch (VaultException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error(HttpStatus.NOT_FOUND.value(), e.getMessage()));
        }
    }

    @GetMapping("/trash")
    public ResponseEntity<ApiResponse<List<VaultTrashItemResponse>>> listTrash() {

        Long userId = JwtAuthContext.getUserId();
        List<VaultTrashItemResponse> result = vaultService.listTrash(userId);
        return ResponseEntity.ok(ApiResponse.success(result));
    }

    @PostMapping("/trash/{itemId}/restore")
    @AuditLog(action = "VAULT_ITEM_RESTORE", targetType = "VAULT_ITEM")
    @RequireDeviceSignature
    public ResponseEntity<ApiResponse<Void>> restoreTrash(
            @PathVariable String itemId) {

        Long userId = JwtAuthContext.getUserId();
        String deviceId = JwtAuthContext.getDeviceId();

        try {
            vaultService.restoreTrash(userId, deviceId, itemId);
            return ResponseEntity.ok(ApiResponse.success());
        } catch (VaultException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error(HttpStatus.NOT_FOUND.value(), e.getMessage()));
        }
    }

    @DeleteMapping("/trash/{itemId}")
    @AuditLog(action = "VAULT_ITEM_PERMANENT_DELETE", targetType = "VAULT_ITEM")
    @RequireDeviceSignature
    public ResponseEntity<ApiResponse<Void>> permanentDelete(
            @PathVariable String itemId) {

        Long userId = JwtAuthContext.getUserId();

        try {
            vaultService.permanentDelete(userId, itemId);
            return ResponseEntity.ok(ApiResponse.success());
        } catch (VaultException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error(HttpStatus.NOT_FOUND.value(), e.getMessage()));
        }
    }
}
