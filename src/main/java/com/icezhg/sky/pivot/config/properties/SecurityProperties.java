package com.icezhg.sky.pivot.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("app.security")
public class SecurityProperties {

    private int rateLimit = 100;
    private int rateLimitWindowSeconds = 60;
    private int biometricMaxFailures = 3;
    private int biometricLockoutMinutes = 5;
    private int tokenExpirySeconds = 60;
}
