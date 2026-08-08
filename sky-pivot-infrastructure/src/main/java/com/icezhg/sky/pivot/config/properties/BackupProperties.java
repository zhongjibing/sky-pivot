package com.icezhg.sky.pivot.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("app.backup")
public class BackupProperties {

    private boolean enabled = false;

    private String directory = "/var/backups/sky-pivot";

    private int retentionDays = 30;

    private String encryptionKeyVaultPath = "backup/encryption-key";

    private String mysqldumpPath = "/usr/bin/mysqldump";

    private String databaseUrl = "jdbc:mysql://localhost:3306/sky_pivot";

    private String databaseUser = "root";

    private String databaseName = "sky_pivot";
}
