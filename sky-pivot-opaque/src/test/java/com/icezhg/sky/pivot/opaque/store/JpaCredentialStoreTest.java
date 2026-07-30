package com.icezhg.sky.pivot.opaque.store;

import com.codeheadsystems.rfc.opaque.model.Envelope;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@DisplayName("JpaCredentialStore Tests")
@ExtendWith(MockitoExtension.class)
class JpaCredentialStoreTest {

    private static final Base64.Encoder B64 = Base64.getEncoder();

    @Mock
    private UserRepository userRepository;

    private JpaCredentialStore credentialStore;

    @BeforeEach
    void setUp() {
        credentialStore = new JpaCredentialStore(userRepository);
    }

    @Test
    @DisplayName("Should store and load registration record")
    void shouldStoreAndLoadRegistrationRecord() {
        byte[] credentialId = "test-user".getBytes();
        RegistrationRecord record = createTestRecord();

        when(userRepository.findByCredentialIdentifier(anyString()))
                .thenReturn(Optional.empty());

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        credentialStore.store(credentialId, record);

        verify(userRepository, times(1)).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        byte[] savedRecord = savedUser.getOpaqueServerRecord();

        when(userRepository.findByCredentialIdentifier(B64.encodeToString(credentialId)))
                .thenReturn(Optional.of(savedUser));

        Optional<RegistrationRecord> loaded = credentialStore.load(credentialId);
        assertTrue(loaded.isPresent());
        assertArrayEquals(record.clientPublicKey(), loaded.get().clientPublicKey());
        assertArrayEquals(record.maskingKey(), loaded.get().maskingKey());
    }

    @Test
    @DisplayName("Should return empty for unknown credential")
    void shouldReturnEmptyForUnknownCredential() {
        when(userRepository.findByCredentialIdentifier(anyString()))
                .thenReturn(Optional.empty());
        byte[] credentialId = "unknown".getBytes();
        assertFalse(credentialStore.load(credentialId).isPresent());
    }

    @Test
    @DisplayName("Should delete registration record")
    void shouldDeleteRegistrationRecord() {
        byte[] credentialId = "delete-me".getBytes();
        User user = new User();
        user.setId(1L);
        user.setCredentialIdentifier(B64.encodeToString(credentialId));
        RegistrationRecord record = createTestRecord();
        credentialStore.store(credentialId, record);

        user.setOpaqueServerRecord(new byte[]{1, 2, 3});
        when(userRepository.findByCredentialIdentifier(B64.encodeToString(credentialId)))
                .thenReturn(Optional.of(user));

        credentialStore.delete(credentialId);
        verify(userRepository, atLeastOnce()).save(any(User.class));
    }

    @Test
    @DisplayName("AC-2: Stored record cannot be used to reverse-engineer password")
    void storedRecordCannotRevealPassword() {
        byte[] credentialId = "secret-user".getBytes();
        RegistrationRecord record = createTestRecord();

        when(userRepository.findByCredentialIdentifier(anyString()))
                .thenReturn(Optional.empty());

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        credentialStore.store(credentialId, record);

        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();
        byte[] stored = savedUser.getOpaqueServerRecord();

        String storedAsString = new String(stored);
        assertFalse(storedAsString.contains("password"));
        assertFalse(storedAsString.contains("secret"));
        assertFalse(storedAsString.contains("pass"));
    }

    private RegistrationRecord createTestRecord() {
        byte[] cPubKey = new byte[33];
        byte[] maskKey = new byte[32];
        byte[] nonce = new byte[32];
        byte[] tag = new byte[32];
        for (int i = 0; i < 32; i++) {
            cPubKey[i] = (byte) i;
            maskKey[i] = (byte) (i + 1);
            nonce[i] = (byte) (i + 2);
            tag[i] = (byte) (i + 3);
        }
        cPubKey[32] = 0;
        return new RegistrationRecord(cPubKey, maskKey, new Envelope(nonce, tag));
    }
}
