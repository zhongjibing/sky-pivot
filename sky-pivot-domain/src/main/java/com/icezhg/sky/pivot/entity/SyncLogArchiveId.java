package com.icezhg.sky.pivot.entity;

import java.io.Serializable;

import lombok.EqualsAndHashCode;

@EqualsAndHashCode
public class SyncLogArchiveId implements Serializable {
    private Long id;
    private Long serverTimestamp;
}
