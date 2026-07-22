package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.LoginResponse;
import com.icezhg.sky.pivot.dto.MiniAppLoginRequest;
import com.icezhg.sky.pivot.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/miniapp")
public class MiniAppAuthController {

    private final AuthService authService;

    public MiniAppAuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ApiResponse<LoginResponse> login(@Valid @RequestBody MiniAppLoginRequest request,
                                             HttpServletRequest httpRequest) {
        String ipAddress = httpRequest.getRemoteAddr();
        LoginResponse response = authService.miniAppLogin(request.code(), request.deviceInfo(), ipAddress);
        return ApiResponse.success(response);
    }
}
