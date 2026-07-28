package com.icezhg.sky.pivot.config.vault;

import com.icezhg.sky.pivot.exception.VaultException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;

@Service
@ConditionalOnProperty(name = "spring.vault.enabled", havingValue = "true")
public class VaultKeyRotationService {

    private static final Logger log = LoggerFactory.getLogger(VaultKeyRotationService.class);

    private final VaultSecretService vaultSecretService;
    private final SecureRandom secureRandom = new SecureRandom();

    public VaultKeyRotationService(VaultSecretService vaultSecretService) {
        this.vaultSecretService = vaultSecretService;
    }

    @Scheduled(cron = "${spring.vault.rotation.st-secret-cron:0 0 3 * * ?}")
    public void rotateStSigningKey() {
        log.info("=== Scheduled ST signing key rotation ===");
        try {
            byte[] newKey = new byte[32];
            secureRandom.nextBytes(newKey);
            String newKeyHex = HexFormat.of().formatHex(newKey);

            vaultSecretService.writeSecret(VaultSecretKeys.JWT_ST_SECRET, newKeyHex);
            log.info("ST signing key rotated successfully at {}",
                    LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        } catch (VaultException e) {
            log.error("ST signing key rotation failed", e);
        }
    }

    public void rotateSecret(String secretKey) {
        log.info("Manual rotation triggered for: {}", secretKey);
        byte[] newKey = new byte[32];
        secureRandom.nextBytes(newKey);
        String newKeyHex = HexFormat.of().formatHex(newKey);

        vaultSecretService.writeSecret(secretKey, newKeyHex);
        log.info("Secret rotated successfully: {}", secretKey);
    }
}
