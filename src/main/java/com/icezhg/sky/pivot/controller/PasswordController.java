package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.PasswordCreateRequest;
import com.icezhg.sky.pivot.dto.PasswordCreateResponse;
import com.icezhg.sky.pivot.dto.PasswordDetailResponse;
import com.icezhg.sky.pivot.dto.PasswordListResponse;
import com.icezhg.sky.pivot.dto.PasswordUpdateRequest;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import com.icezhg.sky.pivot.service.PasswordService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/passwords")
public class PasswordController {

    private final PasswordService passwordService;

    public PasswordController(PasswordService passwordService) {
        this.passwordService = passwordService;
    }

    @GetMapping
    public ApiResponse<Page<PasswordListResponse>> list(
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "updated_at") String sortBy,
            @RequestParam(defaultValue = "desc") String sortOrder,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Long userId = JwtAuthContext.getUserId();
        Page<PasswordListResponse> result = passwordService.listPasswords(userId, search, sortBy, sortOrder, page, size);
        return ApiResponse.success(result);
    }

    @GetMapping("/{id}")
    public ApiResponse<PasswordDetailResponse> view(
            @RequestHeader("X-Token") String tempToken,
            @PathVariable Long id,
            @RequestParam String masterPassword) {
        Long userId = JwtAuthContext.getUserId();
        PasswordDetailResponse result = passwordService.viewPassword(userId, id, masterPassword);
        return ApiResponse.success(result);
    }

    @PostMapping
    public ApiResponse<PasswordCreateResponse> create(
            @Valid @RequestBody PasswordCreateRequest request) {
        Long userId = JwtAuthContext.getUserId();
        PasswordCreateResponse result = passwordService.createPassword(userId, request);
        return ApiResponse.success(result);
    }

    @PutMapping("/{id}")
    public ApiResponse<Void> update(
            @RequestHeader("X-Token") String tempToken,
            @PathVariable Long id,
            @Valid @RequestBody PasswordUpdateRequest request,
            @RequestParam String masterPassword) {
        Long userId = JwtAuthContext.getUserId();
        passwordService.updatePassword(userId, id, request, masterPassword);
        return ApiResponse.success();
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> delete(
            @PathVariable Long id) {
        Long userId = JwtAuthContext.getUserId();
        passwordService.softDeletePassword(userId, id);
        return ApiResponse.success();
    }
}
