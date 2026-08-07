package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;

public record RecoveryChallengeRequest(
    @NotBlank(message = "credentialIdentifier must not be blank")
    String credentialIdentifier
) {}
