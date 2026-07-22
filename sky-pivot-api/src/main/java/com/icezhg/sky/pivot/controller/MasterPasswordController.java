package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.MasterPasswordChangeRequest;
import com.icezhg.sky.pivot.dto.MasterPasswordSetupRequest;
import com.icezhg.sky.pivot.dto.MasterPasswordStatusResponse;
import com.icezhg.sky.pivot.dto.MasterPasswordVerifyRequest;
import com.icezhg.sky.pivot.service.MasterPasswordService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/master-password")
public class MasterPasswordController {

    private final MasterPasswordService masterPasswordService;

    public MasterPasswordController(MasterPasswordService masterPasswordService) {
        this.masterPasswordService = masterPasswordService;
    }

    @PostMapping("/setup")
    public ApiResponse<Void> setup(@Valid @RequestBody MasterPasswordSetupRequest request) {
        masterPasswordService.setupMasterPassword(request.masterPassword());
        return ApiResponse.success();
    }

    @PostMapping("/verify")
    public ApiResponse<Void> verify(@Valid @RequestBody MasterPasswordVerifyRequest request) {
        masterPasswordService.verifyMasterPassword(request.masterPassword());
        return ApiResponse.success();
    }

    @PutMapping("/change")
    public ApiResponse<Void> change(@Valid @RequestBody MasterPasswordChangeRequest request) {
        masterPasswordService.changeMasterPassword(request.currentMasterPassword(), request.newMasterPassword());
        return ApiResponse.success();
    }

    @GetMapping("/status")
    public ApiResponse<MasterPasswordStatusResponse> status() {
        boolean isSet = masterPasswordService.isMasterPasswordSet();
        return ApiResponse.success(new MasterPasswordStatusResponse(isSet));
    }

    @PostMapping("/bind-biometric")
    public ApiResponse<Void> bindBiometric(@Valid @RequestBody MasterPasswordVerifyRequest request) {
        masterPasswordService.bindBiometric(request.masterPassword());
        return ApiResponse.success();
    }
}
