package com.icezhg.sky.pivot.entity;

import jakarta.persistence.*;
import lombok.EqualsAndHashCode;

import java.io.Serializable;

@EqualsAndHashCode
public class SyncLogId implements Serializable {

    private Long id;
    private Long serverTimestamp;
}
