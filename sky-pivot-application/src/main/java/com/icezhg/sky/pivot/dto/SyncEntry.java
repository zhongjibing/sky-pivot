package com.icezhg.sky.pivot.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record SyncEntry(
    @NotBlank(message = "opId must not be blank")
    String opId,

    @NotBlank(message = "operation must not be blank")
    String operation,

    @NotBlank(message = "targetId must not be blank")
    String targetId,

    @NotBlank(message = "targetType must not be blank")
    String targetType,

    @NotNull(message = "targetVersion must not be null")
    Long targetVersion,

    @NotNull(message = "clientTimestamp must not be null")
    Long clientTimestamp,

    @NotNull(message = "lamportClock must not be null")
    Long lamportClock,

    @NotBlank(message = "deviceSignature must not be blank")
    String deviceSignature
) {
    public byte[] signedContentBytes() {
        String content = opId + "|" + operation + "|" + targetId + "|"
                + targetType + "|" + targetVersion + "|"
                + clientTimestamp + "|" + lamportClock;
        return content.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
}
