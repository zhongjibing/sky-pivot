package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.PasswordGenerateRequest;
import com.icezhg.sky.pivot.dto.PasswordGenerateResponse;
import com.icezhg.sky.pivot.dto.PasswordStrengthRequest;
import com.icezhg.sky.pivot.dto.PasswordStrengthResponse;
import com.icezhg.sky.pivot.service.UtilsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/utils")
public class UtilsController {

    private final UtilsService utilsService;

    public UtilsController(UtilsService utilsService) {
        this.utilsService = utilsService;
    }

    @PostMapping("/generate-password")
    public ApiResponse<PasswordGenerateResponse> generatePassword(
            @RequestBody PasswordGenerateRequest request) {
        PasswordGenerateResponse result = utilsService.generatePassword(request);
        return ApiResponse.success(result);
    }

    @PostMapping("/check-strength")
    public ApiResponse<PasswordStrengthResponse> checkStrength(
            @RequestBody PasswordStrengthRequest request) {
        UtilsService.StrengthResult result = utilsService.checkStrength(request.password());
        return ApiResponse.success(new PasswordStrengthResponse(result.score(), result.level()));
    }
}
