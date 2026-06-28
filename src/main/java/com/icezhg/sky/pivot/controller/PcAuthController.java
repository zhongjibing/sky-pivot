package com.icezhg.sky.pivot.controller;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.LoginResponse;
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

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/pc")
public class PcAuthController {

    private final AuthService authService;
    private final Cache<String, QrCodeState> qrCodeCache = Caffeine.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .maximumSize(10000)
            .build();

    public PcAuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login/qrcode")
    public ApiResponse<QrCodeResponse> generateQrCode() {
        String ticket = UUID.randomUUID().toString();
        String qrCodeUrl = "https://password-manager.example.com/pc/login/scan/" + ticket;

        qrCodeCache.put(ticket, new QrCodeState("WAITING", null, Instant.now().plusSeconds(300)));

        return ApiResponse.success(new QrCodeResponse(ticket, qrCodeUrl));
    }

    @GetMapping("/login/status/{ticket}")
    public ApiResponse<QrCodeStatusResponse> checkQrCodeStatus(@PathVariable String ticket) {
        QrCodeState state = qrCodeCache.getIfPresent(ticket);
        if (state == null || state.expiry().isBefore(Instant.now())) {
            return ApiResponse.success(new QrCodeStatusResponse("EXPIRED", null));
        }
        return ApiResponse.success(new QrCodeStatusResponse(state.status(), state.token()));
    }

    @PostMapping("/login/confirm")
    public ApiResponse<Void> confirmQrCodeLogin(@RequestParam String ticket,
                                                @RequestParam String code,
                                                HttpServletRequest httpRequest) {
        QrCodeState state = qrCodeCache.getIfPresent(ticket);
        if (state == null || state.expiry().isBefore(Instant.now())) {
            return ApiResponse.error(400, "QR code expired");
        }

        try {
            String ipAddress = httpRequest.getRemoteAddr();
            LoginResponse loginResponse = authService.pcLogin(code, null, ipAddress);

            qrCodeCache.put(ticket, new QrCodeState("CONFIRMED", loginResponse.token(), state.expiry()));
            return ApiResponse.success();
        } catch (Exception e) {
            return ApiResponse.error(400, "Login failed: " + e.getMessage());
        }
    }

    private record QrCodeState(String status, String token, Instant expiry) {
    }
}
