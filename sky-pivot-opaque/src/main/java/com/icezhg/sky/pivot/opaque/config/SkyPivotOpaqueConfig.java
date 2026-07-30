package com.icezhg.sky.pivot.opaque.config;

import com.codeheadsystems.hofmann.server.auth.JwtManager;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.hofmann.server.store.SessionStore;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.oprf.manager.OprfServerManager;
import com.codeheadsystems.rfc.oprf.model.ServerProcessorDetail;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.icezhg.sky.pivot.config.vault.VaultSecrets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.function.Supplier;

@AutoConfiguration
public class SkyPivotOpaqueConfig {

    private static final Logger log = LoggerFactory.getLogger(SkyPivotOpaqueConfig.class);
    private static final HexFormat HEX = HexFormat.of();

    private final VaultSecrets vaultSecrets;

    public SkyPivotOpaqueConfig(VaultSecrets vaultSecrets) {
        this.vaultSecrets = vaultSecrets;
    }

    @Bean
    @ConditionalOnMissingBean
    public OpaqueConfig opaqueCfg() {
        OprfCipherSuite oprfSuite = OprfCipherSuite.builder()
                .withSuite("P256_SHA256")
                .withRandom(new SecureRandom())
                .build();
        OpaqueCipherSuite suite = new OpaqueCipherSuite(oprfSuite);
        byte[] context = "sky-pivot-v1".getBytes(StandardCharsets.UTF_8);
        return OpaqueConfig.withArgon2id(suite, context, 65536, 3, 1);
    }

    @Bean
    @ConditionalOnMissingBean
    public Server server() {
        String keySeedHex = vaultSecrets.getHofmannServerKeySeedHex();
        String oprfSeedHex = vaultSecrets.getHofmannOprfSeedHex();

        OpaqueConfig cfg = opaqueCfg();
        OpaqueCipherSuite suite = cfg.cipherSuite();
        byte[] keySeed = HEX.parseHex(keySeedHex);
        byte[] oprfSeed = HEX.parseHex(oprfSeedHex);

        OpaqueCipherSuite.AkeKeyPair keyPair = suite.deriveAkeKeyPair(keySeed);
        BigInteger sk = keyPair.privateKey();
        byte[] pk = keyPair.publicKeyBytes();

        int nsk = cfg.Nsk();
        byte[] skBytes = sk.toByteArray();
        byte[] skFixed = new byte[nsk];
        if (skBytes.length > nsk) {
            System.arraycopy(skBytes, skBytes.length - nsk, skFixed, 0, nsk);
        } else {
            System.arraycopy(skBytes, 0, skFixed, nsk - skBytes.length, skBytes.length);
        }

        log.info("OPAQUE Server initialized with Vault-provided keys");
        return new Server(skFixed, pk, oprfSeed, cfg);
    }

    @Bean
    @ConditionalOnMissingBean
    public HofmannOpaqueServerManager opaqueServerManager(Server server, CredentialStore credentialStore,
                                                          JwtManager jwtManager) {
        log.info("HofmannOpaqueServerManager initialized with JPA-backed credential store");
        return new HofmannOpaqueServerManager(server, credentialStore, jwtManager);
    }

    @Bean
    @ConditionalOnMissingBean
    public Supplier<ServerProcessorDetail> serverProcessorDetailSupplier() {
        String masterKeyHex = vaultSecrets.getHofmannOprfMasterKeyHex();
        BigInteger masterKey = new BigInteger(masterKeyHex, 16);
        ServerProcessorDetail detail = new ServerProcessorDetail(masterKey, "hofmann-oprf-v1");
        return () -> detail;
    }

    @Bean
    @ConditionalOnMissingBean
    public OprfServerManager oprfServerManager(SecureRandom secureRandom,
                                               Supplier<ServerProcessorDetail> serverProcessorDetailSupplier) {
        OprfCipherSuite oprfSuite = OprfCipherSuite.builder()
                .withSuite("P256_SHA256")
                .withRandom(secureRandom)
                .build();
        return new OprfServerManager(oprfSuite, serverProcessorDetailSupplier);
    }
}
