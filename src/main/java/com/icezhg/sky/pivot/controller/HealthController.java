package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.HealthSummaryResponse;
import com.icezhg.sky.pivot.dto.PasswordListResponse;
import com.icezhg.sky.pivot.entity.Password;
import com.icezhg.sky.pivot.repository.PasswordRepository;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import com.icezhg.sky.pivot.service.HealthService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/passwords/health")
public class HealthController {

    private final PasswordRepository passwordRepository;
    private final HealthService healthService;

    public HealthController(PasswordRepository passwordRepository,
                            HealthService healthService) {
        this.passwordRepository = passwordRepository;
        this.healthService = healthService;
    }

    @GetMapping("/summary")
    public ApiResponse<HealthSummaryResponse> summary() {
        Long userId = JwtAuthContext.getUserId();

        long weak = passwordRepository.countByUserIdAndHealthLevel(userId, "WEAK");
        long fair = passwordRepository.countByUserIdAndHealthLevel(userId, "FAIR");
        long strong = passwordRepository.countByUserIdAndHealthLevel(userId, "STRONG");
        long veryStrong = passwordRepository.countByUserIdAndHealthLevel(userId, "VERY_STRONG");

        return ApiResponse.success(new HealthSummaryResponse(weak, fair, strong, veryStrong));
    }

    @GetMapping("/weak")
    public ApiResponse<java.util.List<PasswordListResponse>> weakPasswords() {
        Long userId = JwtAuthContext.getUserId();

        java.util.List<Password> weakPasswords = passwordRepository.findByUserIdAndHealthLevel(userId, "WEAK");
        java.util.List<PasswordListResponse> result = weakPasswords.stream()
                .map(p -> new PasswordListResponse(p.getId(), p.getTitle(), p.getUrl(), p.getAccount(), p.getHealthLevel(), p.getUpdatedAt()))
                .toList();

        return ApiResponse.success(result);
    }
}
