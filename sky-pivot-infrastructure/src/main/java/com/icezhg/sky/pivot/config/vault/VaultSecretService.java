package com.icezhg.sky.pivot.config.vault;

import com.icezhg.sky.pivot.exception.VaultException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponseSupport;

import java.util.Map;

public class VaultSecretService {

    private static final Logger log = LoggerFactory.getLogger(VaultSecretService.class);

    private final VaultTemplate vaultTemplate;
    private final String mount;

    public VaultSecretService(VaultTemplate vaultTemplate, String mount) {
        this.vaultTemplate = vaultTemplate;
        this.mount = mount;
    }

    public String readSecret(String path) {
        String fullPath = mount + "/data/" + VaultSecretKeys.BASE_PATH + "/" + path;
        try {
            VaultResponseSupport<Map> response = vaultTemplate.read(fullPath, Map.class);
            if (response == null || response.getData() == null) {
                throw new VaultException("Secret not found at path: " + fullPath);
            }
            Map<String, Object> data = response.getData();
            @SuppressWarnings("unchecked")
            Map<String, Object> innerData = (Map<String, Object>) data.get("data");
            if (innerData == null) {
                throw new VaultException("Secret data is empty at path: " + fullPath);
            }
            Object value = innerData.get("value");
            if (value == null) {
                throw new VaultException("Secret value is null at path: " + fullPath);
            }
            log.debug("Successfully read Vault secret: {}", path);
            return value.toString();
        } catch (VaultException e) {
            throw e;
        } catch (Exception e) {
            throw new VaultException("Failed to read secret from Vault at path: " + fullPath, e);
        }
    }

    public void writeSecret(String path, String value) {
        String fullPath = mount + "/data/" + VaultSecretKeys.BASE_PATH + "/" + path;
        try {
            Map<String, Object> body = Map.of("data", Map.of("value", value));
            vaultTemplate.write(fullPath, body);
            log.info("Successfully wrote Vault secret: {}", path);
        } catch (Exception e) {
            throw new VaultException("Failed to write secret to Vault at path: " + fullPath, e);
        }
    }

    public boolean ping() {
        try {
            vaultTemplate.read(mount + "/data/" + VaultSecretKeys.BASE_PATH + "/health", Map.class);
            return true;
        } catch (Exception e) {
            log.debug("Vault ping failed: {}", e.getMessage());
            return false;
        }
    }
}
