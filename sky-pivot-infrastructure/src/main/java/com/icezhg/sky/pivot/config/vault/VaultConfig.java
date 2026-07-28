package com.icezhg.sky.pivot.config.vault;

import com.icezhg.sky.pivot.config.properties.VaultProperties;
import com.icezhg.sky.pivot.exception.VaultException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.vault.authentication.AppRoleAuthentication;
import org.springframework.vault.authentication.AppRoleAuthenticationOptions;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.web.client.RestTemplate;

import java.net.Proxy;
import java.time.Duration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "spring.vault.enabled", havingValue = "true")
public class VaultConfig {

    private static final Logger log = LoggerFactory.getLogger(VaultConfig.class);

    @Bean
    public VaultEndpoint vaultEndpoint(VaultProperties properties) {
        VaultEndpoint endpoint = VaultEndpoint.create(properties.getHost(), properties.getPort());
        endpoint.setScheme(properties.getScheme());
        log.info("Vault endpoint configured: {}://{}:{}",
                properties.getScheme(), properties.getHost(), properties.getPort());
        return endpoint;
    }

    @Bean
    public ClientAuthentication clientAuthentication(VaultProperties properties) {
        VaultProperties.AppRole appRole = properties.getAppRole();
        if (appRole.getRoleId() == null || appRole.getRoleId().isBlank()) {
            throw new VaultException("Vault AppRole role-id is required when Vault is enabled");
        }
        if (appRole.getSecretId() == null || appRole.getSecretId().isBlank()) {
            throw new VaultException("Vault AppRole secret-id is required when Vault is enabled");
        }
        RestTemplate restTemplate = createRestTemplate(properties);
        AppRoleAuthenticationOptions options = AppRoleAuthenticationOptions.builder()
                .roleId(AppRoleAuthenticationOptions.RoleId.provided(appRole.getRoleId()))
                .secretId(AppRoleAuthenticationOptions.SecretId.provided(appRole.getSecretId()))
                .build();
        AppRoleAuthentication auth = new AppRoleAuthentication(options, restTemplate);
        log.info("Vault AppRole authentication configured (role-id prefix: {})",
                appRole.getRoleId().substring(0, Math.min(8, appRole.getRoleId().length())));
        return auth;
    }

    @Bean
    public VaultTemplate vaultTemplate(VaultEndpoint endpoint, ClientAuthentication clientAuthentication) {
        VaultTemplate vaultTemplate = new VaultTemplate(endpoint, clientAuthentication);
        log.info("VaultTemplate initialized");
        return vaultTemplate;
    }

    @Bean
    public VaultSecrets vaultSecrets() {
        return new VaultSecrets();
    }

    @Bean
    public VaultSecretService vaultSecretService(VaultTemplate vaultTemplate, VaultProperties properties) {
        String mount = properties.getKv().getBackend();
        log.info("VaultSecretService initialized (mount: {})", mount);
        return new VaultSecretService(vaultTemplate, mount);
    }

    private RestTemplate createRestTemplate(VaultProperties properties) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setProxy(Proxy.NO_PROXY);
        requestFactory.setConnectTimeout(Duration.ofSeconds(properties.getConnectionTimeoutSeconds()));
        requestFactory.setReadTimeout(Duration.ofSeconds(properties.getReadTimeoutSeconds()));
        return new RestTemplate(requestFactory);
    }
}
