package com.icezhg.sky.pivot.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("spring.vault")
public class VaultProperties {

    private boolean enabled = false;
    private String host = "localhost";
    private int port = 8200;
    private String scheme = "http";
    private String authentication = "APPROLE";

    private int connectionTimeoutSeconds = 5;
    private int readTimeoutSeconds = 10;

    private AppRole appRole = new AppRole();
    private Kv kv = new Kv();
    private boolean failFast = true;

    @Data
    public static class AppRole {
        private String roleId;
        private String secretId;
    }

    @Data
    public static class Kv {
        private boolean enabled = true;
        private String backend = "secret";
    }
}
