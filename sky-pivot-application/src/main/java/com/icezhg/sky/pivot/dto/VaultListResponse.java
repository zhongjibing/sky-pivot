package com.icezhg.sky.pivot.dto;

import java.util.List;

public record VaultListResponse(
    List<VaultItemResponse> items,
    long syncVersion
) {}
