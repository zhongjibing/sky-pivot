package com.icezhg.sky.pivot.config.vault;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "spring.vault.enabled", havingValue = "true")
public class VaultHealthIndicator implements HealthIndicator {

    private static final Logger log = LoggerFactory.getLogger(VaultHealthIndicator.class);

    private final VaultSecretService vaultSecretService;
    private final VaultSecrets vaultSecrets;

    public VaultHealthIndicator(VaultSecretService vaultSecretService, VaultSecrets vaultSecrets) {
        this.vaultSecretService = vaultSecretService;
        this.vaultSecrets = vaultSecrets;
    }

    @Override
    public Health health() {
        try {
            boolean reachable = vaultSecretService.ping();
            boolean allLoaded = vaultSecrets.allRequiredLoaded();

            if (reachable && allLoaded) {
                return Health.up()
                        .withDetail("vault", "reachable")
                        .withDetail("secretsLoaded", vaultSecrets.loadedCount())
                        .withDetail("secretsRequired", VaultSecretKeys.REQUIRED_SECRETS.length)
                        .build();
            } else if (!reachable) {
                log.warn("Vault health check failed: vault is not reachable");
                return Health.down()
                        .withDetail("vault", "unreachable")
                        .withDetail("secretsLoaded", vaultSecrets.loadedCount())
                        .build();
            } else {
                log.warn("Vault health check: not all required secrets loaded");
                return Health.down()
                        .withDetail("vault", "reachable")
                        .withDetail("secretsLoaded", vaultSecrets.loadedCount())
                        .withDetail("secretsRequired", VaultSecretKeys.REQUIRED_SECRETS.length)
                        .withDetail("message", "Not all required secrets are loaded")
                        .build();
            }
        } catch (Exception e) {
            log.error("Vault health check failed", e);
            return Health.down()
                    .withDetail("vault", "error")
                    .withDetail("error", e.getMessage())
                    .build();
        }
    }
}
