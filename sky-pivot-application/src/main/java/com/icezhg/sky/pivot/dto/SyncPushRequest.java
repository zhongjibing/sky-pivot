package com.icezhg.sky.pivot.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

public record SyncPushRequest(
    @NotEmpty(message = "entries must not be empty")
    @Valid
    List<SyncEntry> entries
) {}
