package com.icezhg.sky.pivot.config.properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Vault Properties Tests")
class VaultPropertiesTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(EnableProps.class);

    @TestConfiguration
    @EnableConfigurationProperties(VaultProperties.class)
    static class EnableProps {
    }

    @Test
    @DisplayName("Should bind default values")
    void shouldBindDefaultValues() {
        contextRunner.run(ctx -> {
            VaultProperties props = ctx.getBean(VaultProperties.class);
            assertFalse(props.isEnabled());
            assertEquals("localhost", props.getHost());
            assertEquals(8200, props.getPort());
            assertEquals("http", props.getScheme());
            assertEquals("APPROLE", props.getAuthentication());
            assertEquals(5, props.getConnectionTimeoutSeconds());
            assertEquals(10, props.getReadTimeoutSeconds());
            assertTrue(props.getKv().isEnabled());
            assertEquals("secret", props.getKv().getBackend());
        });
    }

    @Test
    @DisplayName("Should bind custom values from properties")
    void shouldBindCustomValues() {
        contextRunner
                .withPropertyValues(
                        "spring.vault.enabled=true",
                        "spring.vault.host=vault.example.com",
                        "spring.vault.port=8201",
                        "spring.vault.scheme=https",
                        "spring.vault.authentication=APPROLE",
                        "spring.vault.app-role.role-id=my-role-id",
                        "spring.vault.app-role.secret-id=my-secret-id",
                        "spring.vault.kv.backend=my-secrets",
                        "spring.vault.connection-timeout-seconds=10",
                        "spring.vault.read-timeout-seconds=30"
                )
                .run(ctx -> {
                    VaultProperties props = ctx.getBean(VaultProperties.class);
                    assertTrue(props.isEnabled());
                    assertEquals("vault.example.com", props.getHost());
                    assertEquals(8201, props.getPort());
                    assertEquals("https", props.getScheme());
                    assertEquals("APPROLE", props.getAuthentication());
                    assertEquals("my-role-id", props.getAppRole().getRoleId());
                    assertEquals("my-secret-id", props.getAppRole().getSecretId());
                    assertEquals("my-secrets", props.getKv().getBackend());
                    assertEquals(10, props.getConnectionTimeoutSeconds());
                    assertEquals(30, props.getReadTimeoutSeconds());
                });
    }

    @Test
    @DisplayName("Should bind properties from environment variable placeholders")
    void shouldBindFromEnvPlaceholders() {
        contextRunner
                .withPropertyValues(
                        "spring.vault.host=${VAULT_HOST:localhost}",
                        "spring.vault.port=${VAULT_PORT:8200}",
                        "spring.vault.app-role.role-id=${VAULT_ROLE_ID:}",
                        "spring.vault.app-role.secret-id=${VAULT_SECRET_ID:}"
                )
                .run(ctx -> {
                    VaultProperties props = ctx.getBean(VaultProperties.class);
                    assertEquals("localhost", props.getHost());
                    assertEquals(8200, props.getPort());
                });
    }
}
