package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.EqualsAndHashCode;

import java.io.Serializable;
import java.time.LocalDateTime;

@EqualsAndHashCode
public class AuditLogId implements Serializable {

    private Long id;
    private LocalDateTime createdAt;
}
