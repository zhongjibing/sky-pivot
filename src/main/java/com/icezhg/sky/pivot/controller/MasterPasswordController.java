package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.MasterPasswordChangeRequest;
import com.icezhg.sky.pivot.dto.MasterPasswordSetupRequest;
import com.icezhg.sky.pivot.dto.MasterPasswordStatusResponse;
import com.icezhg.sky.pivot.dto.MasterPasswordVerifyRequest;
import com.icezhg.sky.pivot.dto.TokenResponse;
import com.icezhg.sky.pivot.security.JwtService;
import com.icezhg.sky.pivot.security.TemporaryTokenService;
import com.icezhg.sky.pivot.security.TemporaryTokenService.TokenType;
import com.icezhg.sky.pivot.service.MasterPasswordService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/master-password")
public class MasterPasswordController {

    private final MasterPasswordService masterPasswordService;
    private final JwtService jwtService;
    private final TemporaryTokenService temporaryTokenService;

    public MasterPasswordController(MasterPasswordService masterPasswordService,
                                    JwtService jwtService,
                                    TemporaryTokenService temporaryTokenService) {
        this.masterPasswordService = masterPasswordService;
        this.jwtService = jwtService;
        this.temporaryTokenService = temporaryTokenService;
    }

    @PostMapping("/setup")
    public ApiResponse<Void> setup(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
                                   @Valid @RequestBody MasterPasswordSetupRequest request) {
        Long userId = jwtService.validateToken(extractToken(authHeader));
        masterPasswordService.setupMasterPassword(userId, request.masterPassword());
        return ApiResponse.success();
    }

    @PostMapping("/verify")
    public ApiResponse<TokenResponse> verify(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
                                             @Valid @RequestBody MasterPasswordVerifyRequest request) {
        Long userId = jwtService.validateToken(extractToken(authHeader));
        String token = masterPasswordService.verifyMasterPassword(userId, request.masterPassword());
        return ApiResponse.success(new TokenResponse(token));
    }

    @PutMapping("/change")
    public ApiResponse<Void> change(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
                                    @RequestHeader("X-Token") String tempToken,
                                    @Valid @RequestBody MasterPasswordChangeRequest request) {
        Long userId = jwtService.validateToken(extractToken(authHeader));

        TemporaryTokenService.TokenData tokenData = temporaryTokenService.consumeToken(tempToken, TokenType.MASTER_PASSWORD);
        if (tokenData == null || !tokenData.userId().equals(userId)) {
            return ApiResponse.error(401, "Invalid or expired token");
        }

        masterPasswordService.changeMasterPassword(userId, request.currentMasterPassword(), request.newMasterPassword());
        return ApiResponse.success();
    }

    @GetMapping("/status")
    public ApiResponse<MasterPasswordStatusResponse> status(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        Long userId = jwtService.validateToken(extractToken(authHeader));
        boolean isSet = masterPasswordService.isMasterPasswordSet(userId);
        return ApiResponse.success(new MasterPasswordStatusResponse(isSet));
    }

    @PostMapping("/bind-biometric")
    public ApiResponse<Void> bindBiometric(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
                                           @Valid @RequestBody MasterPasswordVerifyRequest request) {
        Long userId = jwtService.validateToken(extractToken(authHeader));
        masterPasswordService.bindBiometric(userId, request.masterPassword());
        return ApiResponse.success();
    }

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new RuntimeException("Missing or invalid Authorization header");
    }
}
