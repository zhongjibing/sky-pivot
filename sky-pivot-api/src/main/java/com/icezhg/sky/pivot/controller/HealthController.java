package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.HealthSummaryResponse;
import com.icezhg.sky.pivot.dto.PasswordListResponse;
import com.icezhg.sky.pivot.service.HealthService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/passwords/health")
public class HealthController {

    private final HealthService healthService;

    public HealthController(HealthService healthService) {
        this.healthService = healthService;
    }

    @GetMapping("/summary")
    public ApiResponse<HealthSummaryResponse> summary() {
        HealthSummaryResponse result = healthService.getSummary();
        return ApiResponse.success(result);
    }

    @GetMapping("/weak")
    public ApiResponse<List<PasswordListResponse>> weakPasswords() {
        List<PasswordListResponse> result = healthService.getWeakPasswords();
        return ApiResponse.success(result);
    }
}
