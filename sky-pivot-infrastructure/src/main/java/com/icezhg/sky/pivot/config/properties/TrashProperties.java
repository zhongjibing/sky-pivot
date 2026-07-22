package com.icezhg.sky.pivot.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("app.trash")
public class TrashProperties {

    private int retentionDays = 30;
}
