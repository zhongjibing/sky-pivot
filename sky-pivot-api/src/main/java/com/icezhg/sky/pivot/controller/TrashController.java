package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.PasswordDetailResponse;
import com.icezhg.sky.pivot.dto.TrashItemResponse;
import com.icezhg.sky.pivot.service.TrashService;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/passwords/trash")
public class TrashController {

    private final TrashService trashService;

    public TrashController(TrashService trashService) {
        this.trashService = trashService;
    }

    @GetMapping
    public ApiResponse<List<TrashItemResponse>> list() {
        List<TrashItemResponse> result = trashService.listTrash();
        return ApiResponse.success(result);
    }

    @GetMapping("/{id}")
    public ApiResponse<PasswordDetailResponse> view(
            @PathVariable Long id,
            @RequestParam String masterPassword) {
        PasswordDetailResponse result = trashService.viewTrashDetail(id, masterPassword);
        return ApiResponse.success(result);
    }

    @PutMapping("/{id}/restore")
    public ApiResponse<Void> restore(
            @PathVariable Long id) {
        trashService.restorePassword(id);
        return ApiResponse.success();
    }

    @DeleteMapping("/{id}")
    public ApiResponse<Void> permanentlyDelete(
            @PathVariable Long id) {
        trashService.permanentlyDelete(id);
        return ApiResponse.success();
    }
}
