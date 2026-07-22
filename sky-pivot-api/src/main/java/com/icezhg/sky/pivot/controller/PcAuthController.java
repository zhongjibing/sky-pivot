package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.QrCodeResponse;
import com.icezhg.sky.pivot.dto.QrCodeStatusResponse;
import com.icezhg.sky.pivot.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/pc")
public class PcAuthController {

    private final AuthService authService;

    public PcAuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login/qrcode")
    public ApiResponse<QrCodeResponse> generateQrCode() {
        QrCodeResponse result = authService.generateQrCode();
        return ApiResponse.success(result);
    }

    @GetMapping("/login/status/{ticket}")
    public ApiResponse<QrCodeStatusResponse> checkQrCodeStatus(@PathVariable String ticket) {
        QrCodeStatusResponse result = authService.checkQrCodeStatus(ticket);
        return ApiResponse.success(result);
    }

    @PostMapping("/login/confirm")
    public ApiResponse<Void> confirmQrCodeLogin(@RequestParam String ticket,
                                                @RequestParam String code,
                                                HttpServletRequest httpRequest) {
        String ipAddress = httpRequest.getRemoteAddr();
        authService.confirmQrCodeLogin(ticket, code, ipAddress);
        return ApiResponse.success();
    }
}
