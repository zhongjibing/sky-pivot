package com.icezhg.sky.pivot.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("app.login-history")
public class LoginHistoryProperties {

    private int retentionMonths = 12;
}
