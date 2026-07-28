package com.icezhg.sky.pivot.config.vault;

import com.icezhg.sky.pivot.config.properties.VaultProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertFalse;

@DisplayName("Vault Config Tests")
@Tag("unit")
class VaultConfigTest {

    @Test
    @DisplayName("Should NOT create VaultTemplate bean when vault is disabled")
    void shouldNotCreateVaultTemplateWhenDisabled() {
        var runner = new ApplicationContextRunner()
                .withPropertyValues("spring.vault.enabled=false")
                .withUserConfiguration(VaultConfig.class, VaultPropsConfig.class);

        runner.run(ctx -> assertFalse(ctx.containsBean("vaultTemplate")));
    }

    @Test
    @DisplayName("Should NOT create VaultSecretService bean when vault is disabled")
    void shouldNotCreateVaultSecretServiceWhenDisabled() {
        var runner = new ApplicationContextRunner()
                .withPropertyValues("spring.vault.enabled=false")
                .withUserConfiguration(VaultConfig.class, VaultPropsConfig.class);

        runner.run(ctx -> assertFalse(ctx.containsBean("vaultSecretService")));
    }

    @Test
    @DisplayName("Should NOT create VaultHealthIndicator bean when vault is disabled")
    void shouldNotCreateVaultHealthIndicatorWhenDisabled() {
        var runner = new ApplicationContextRunner()
                .withPropertyValues("spring.vault.enabled=false")
                .withUserConfiguration(VaultHealthIndicator.class);

        runner.run(ctx -> assertFalse(ctx.containsBean("vaultHealthIndicator")));
    }

    @org.springframework.boot.test.context.TestConfiguration
    @EnableConfigurationProperties(VaultProperties.class)
    static class VaultPropsConfig {
    }
}
