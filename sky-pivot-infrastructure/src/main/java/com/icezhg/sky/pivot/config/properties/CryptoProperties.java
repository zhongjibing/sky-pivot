package com.icezhg.sky.pivot.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("app.crypto")
public class CryptoProperties {

    private int pbkdf2Iterations = 600000;
    private int pbkdf2KeyLength = 256;
    private int bcryptCost = 12;
}
