package com.icezhg.sky.pivot.opaque.dto;

import jakarta.validation.constraints.NotBlank;

public record EmergencyAuthChallengeRequest(
        @NotBlank String credentialIdentifier
) {}
