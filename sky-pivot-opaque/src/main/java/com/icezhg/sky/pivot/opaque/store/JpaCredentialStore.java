package com.icezhg.sky.pivot.opaque.store;

import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.rfc.opaque.model.Envelope;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Component
public class JpaCredentialStore implements CredentialStore {

    private static final Logger log = LoggerFactory.getLogger(JpaCredentialStore.class);
    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final UserRepository userRepository;

    public JpaCredentialStore(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public void store(byte[] credentialIdentifier, RegistrationRecord record) {
        String credId = B64.encodeToString(credentialIdentifier);
        User user = userRepository.findByCredentialIdentifier(credId)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setCredentialIdentifier(credId);
                    newUser.setSalt("");
                    newUser.setEncryptedDek("");
                    newUser.setEncryptedUrkRecovery("");
                    newUser.setRecoverySalt("");
                    newUser.setRecoveryKeyHash("");
                    return newUser;
                });
        byte[] serialized = serializeRecord(record);
        user.setOpaqueServerRecord(serialized);
        user.setOpaqueClientRecord(serialized);
        userRepository.save(user);
        log.info("Stored OPAQUE registration record for credential: {}", credId);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<RegistrationRecord> load(byte[] credentialIdentifier) {
        String credId = B64.encodeToString(credentialIdentifier);
        return userRepository.findByCredentialIdentifier(credId)
                .map(user -> {
                    RegistrationRecord record = deserializeRecord(user.getOpaqueServerRecord());
                    log.debug("Loaded OPAQUE registration record for credential: {}", credId);
                    return record;
                });
    }

    @Override
    @Transactional
    public void delete(byte[] credentialIdentifier) {
        String credId = B64.encodeToString(credentialIdentifier);
        userRepository.findByCredentialIdentifier(credId).ifPresent(user -> {
            user.setOpaqueServerRecord(null);
            user.setOpaqueClientRecord(null);
            userRepository.save(user);
            log.info("Deleted OPAQUE registration record for credential: {}", credId);
        });
    }

    private byte[] serializeRecord(RegistrationRecord record) {
        byte[] cPubKey = record.clientPublicKey();
        byte[] maskKey = record.maskingKey();
        byte[] nonce = record.envelope().envelopeNonce();
        byte[] tag = record.envelope().authTag();

        int totalLen = 4 + cPubKey.length + 4 + maskKey.length + 4 + nonce.length + 4 + tag.length;
        ByteBuffer buf = ByteBuffer.allocate(totalLen);
        buf.putInt(cPubKey.length);
        buf.put(cPubKey);
        buf.putInt(maskKey.length);
        buf.put(maskKey);
        buf.putInt(nonce.length);
        buf.put(nonce);
        buf.putInt(tag.length);
        buf.put(tag);
        return buf.array();
    }

    private RegistrationRecord deserializeRecord(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data);

        int cPubKeyLen = buf.getInt();
        byte[] cPubKey = new byte[cPubKeyLen];
        buf.get(cPubKey);

        int maskKeyLen = buf.getInt();
        byte[] maskKey = new byte[maskKeyLen];
        buf.get(maskKey);

        int nonceLen = buf.getInt();
        byte[] nonce = new byte[nonceLen];
        buf.get(nonce);

        int tagLen = buf.getInt();
        byte[] tag = new byte[tagLen];
        buf.get(tag);

        return new RegistrationRecord(cPubKey, maskKey, new Envelope(nonce, tag));
    }
}
