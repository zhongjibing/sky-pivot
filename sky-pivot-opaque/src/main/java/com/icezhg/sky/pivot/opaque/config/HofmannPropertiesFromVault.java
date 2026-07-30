package com.icezhg.sky.pivot.opaque.config;

import com.icezhg.sky.pivot.config.vault.VaultSecrets;

public class HofmannPropertiesFromVault {

    private final VaultSecrets vaultSecrets;

    public HofmannPropertiesFromVault(VaultSecrets vaultSecrets) {
        this.vaultSecrets = vaultSecrets;
    }

    public String getServerKeySeedHex() {
        return vaultSecrets.getHofmannServerKeySeedHex();
    }

    public String getOprfSeedHex() {
        return vaultSecrets.getHofmannOprfSeedHex();
    }

    public String getOprfMasterKeyHex() {
        return vaultSecrets.getHofmannOprfMasterKeyHex();
    }

    public String getJwtStSecretHex() {
        return vaultSecrets.getJwtStSecretHex();
    }
}
