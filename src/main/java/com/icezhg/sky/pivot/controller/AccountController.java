package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.AccountDeletePreviewResponse;
import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import com.icezhg.sky.pivot.security.TemporaryTokenService;
import com.icezhg.sky.pivot.security.TemporaryTokenService.TokenType;
import com.icezhg.sky.pivot.service.AccountService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/account")
public class AccountController {

    private final AccountService accountService;
    private final TemporaryTokenService temporaryTokenService;

    public AccountController(AccountService accountService,
                             TemporaryTokenService temporaryTokenService) {
        this.accountService = accountService;
        this.temporaryTokenService = temporaryTokenService;
    }

    @GetMapping("/delete/preview")
    public ApiResponse<AccountDeletePreviewResponse> preview() {
        Long userId = JwtAuthContext.getUserId();
        AccountDeletePreviewResponse result = accountService.previewDeletion(userId);
        return ApiResponse.success(result);
    }

    @PostMapping("/delete")
    public ApiResponse<Void> delete(
            @RequestHeader("X-Token") String tempToken) {
        Long userId = JwtAuthContext.getUserId();

        TemporaryTokenService.TokenData tokenData = temporaryTokenService.consumeToken(tempToken, TokenType.MASTER_PASSWORD);
        if (tokenData == null || !tokenData.userId().equals(userId)) {
            return ApiResponse.error(401, "Invalid or expired token");
        }

        accountService.deleteAccount(userId);
        return ApiResponse.success();
    }
}
