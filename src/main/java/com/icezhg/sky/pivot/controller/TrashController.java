package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.PasswordDetailResponse;
import com.icezhg.sky.pivot.dto.TrashItemResponse;
import com.icezhg.sky.pivot.security.JwtService;
import com.icezhg.sky.pivot.service.TrashService;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/passwords/trash")
public class TrashController {

    private final TrashService trashService;
    private final JwtService jwtService;

    public TrashController(TrashService trashService, JwtService jwtService) {
        this.trashService = trashService;
        this.jwtService = jwtService;
    }

    @GetMapping
    public ApiResponse<List<TrashItemResponse>> list(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        Long userId = jwtService.validateToken(extractToken(authHeader));
        List<TrashItemResponse> result = trashService.listTrash(userId);
        return ApiResponse.success(result);
    }

    @GetMapping("/{id}")
    public ApiResponse<PasswordDetailResponse> view(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            @PathVariable Long id,
            @RequestParam String masterPassword) {
        Long userId = jwtService.validateToken(extractToken(authHeader));
        PasswordDetailResponse result = trashService.viewTrashDetail(userId, id, masterPassword);
        return ApiResponse.success(result);
    }

    @PutMapping("/{id}/restore")
    public ApiResponse<Void> restore(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            @PathVariable Long id) {
        Long userId = jwtService.validateToken(extractToken(authHeader));
        trashService.restorePassword(userId, id);
        return ApiResponse.success();
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> permanentlyDelete(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            @PathVariable Long id) {
        Long userId = jwtService.validateToken(extractToken(authHeader));
        trashService.permanentlyDelete(userId, id);
        return ApiResponse.success();
    }

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new RuntimeException("Missing or invalid Authorization header");
    }
}
