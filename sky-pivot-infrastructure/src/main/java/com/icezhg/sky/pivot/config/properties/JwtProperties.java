package com.icezhg.sky.pivot.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("app.jwt")
public class JwtProperties {

    private String secret;
    private int miniappExpiryDays = 7;
    private int pcExpiryHours = 2;
}
