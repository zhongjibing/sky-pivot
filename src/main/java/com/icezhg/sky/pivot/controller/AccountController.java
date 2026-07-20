package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.AccountDeletePreviewResponse;
import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import com.icezhg.sky.pivot.service.AccountService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/account")
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping("/delete/preview")
    public ApiResponse<AccountDeletePreviewResponse> preview() {
        Long userId = JwtAuthContext.getUserId();
        AccountDeletePreviewResponse result = accountService.previewDeletion(userId);
        return ApiResponse.success(result);
    }

    @PostMapping("/delete")
    public ApiResponse<Void> delete() {
        Long userId = JwtAuthContext.getUserId();
        accountService.deleteAccount(userId);
        return ApiResponse.success();
    }
}
