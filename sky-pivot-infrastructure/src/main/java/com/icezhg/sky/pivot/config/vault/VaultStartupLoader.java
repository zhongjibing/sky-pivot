package com.icezhg.sky.pivot.config.vault;

import com.icezhg.sky.pivot.exception.VaultException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "spring.vault.enabled", havingValue = "true")
public class VaultStartupLoader {

    private static final Logger log = LoggerFactory.getLogger(VaultStartupLoader.class);

    private final VaultSecretService vaultSecretService;
    private final VaultSecrets vaultSecrets;

    public VaultStartupLoader(VaultSecretService vaultSecretService, VaultSecrets vaultSecrets) {
        this.vaultSecretService = vaultSecretService;
        this.vaultSecrets = vaultSecrets;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void loadSecretsOnStartup() {
        log.info("=== Vault startup: loading required secrets ===");
        int loaded = 0;
        int failed = 0;

        for (String secretKey : VaultSecretKeys.REQUIRED_SECRETS) {
            try {
                String value = vaultSecretService.readSecret(secretKey);
                vaultSecrets.put(secretKey, value);
                loaded++;
                log.info("  [LOADED] {}", secretKey);
            } catch (VaultException e) {
                failed++;
                log.error("  [FAILED] {}: {}", secretKey, e.getMessage());
            }
        }

        log.info("=== Vault startup: {}/{} required secrets loaded, {} failed ===",
                loaded, VaultSecretKeys.REQUIRED_SECRETS.length, failed);

        if (!vaultSecrets.allRequiredLoaded()) {
            throw new VaultException(
                    "Failed to load all required Vault secrets. Missing: " +
                    String.join(", ", getMissingSecrets()));
        }

        log.info("Vault secrets loaded successfully. Total cached secrets: {}", vaultSecrets.loadedCount());
    }

    private String[] getMissingSecrets() {
        return java.util.Arrays.stream(VaultSecretKeys.REQUIRED_SECRETS)
                .filter(key -> !vaultSecrets.isLoaded(key))
                .toArray(String[]::new);
    }
}
