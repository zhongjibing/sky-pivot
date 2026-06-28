package com.icezhg.sky.pivot.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServiceTest {

    private CryptoService cryptoService;

    @BeforeEach
    void setUp() {
        cryptoService = new CryptoService();
        ReflectionTestUtils.setField(cryptoService, "pbkdf2Iterations", 600000);
        ReflectionTestUtils.setField(cryptoService, "pbkdf2KeyLength", 256);
        ReflectionTestUtils.setField(cryptoService, "bcryptCost", 12);
    }

    @Test
    void generateSalt_returnsCorrectLength() {
        byte[] salt = cryptoService.generateSalt(16);
        assertEquals(16, salt.length);
    }

    @Test
    void generateSalt_returnsUniqueValues() {
        byte[] salt1 = cryptoService.generateSalt(16);
        byte[] salt2 = cryptoService.generateSalt(16);
        assertFalse(java.util.Arrays.equals(salt1, salt2));
    }

    @Test
    void deriveKek_producesConsistentOutput() {
        byte[] salt = cryptoService.generateSalt(16);
        byte[] kek1 = cryptoService.deriveKek("test-password", salt);
        byte[] kek2 = cryptoService.deriveKek("test-password", salt);
        assertArrayEquals(kek1, kek2);
    }

    @Test
    void deriveKek_differentPasswordsProduceDifferentKeys() {
        byte[] salt = cryptoService.generateSalt(16);
        byte[] kek1 = cryptoService.deriveKek("password1", salt);
        byte[] kek2 = cryptoService.deriveKek("password2", salt);
        assertFalse(java.util.Arrays.equals(kek1, kek2));
    }

    @Test
    void deriveKek_differentSaltsProduceDifferentKeys() {
        byte[] salt1 = cryptoService.generateSalt(16);
        byte[] salt2 = cryptoService.generateSalt(16);
        byte[] kek1 = cryptoService.deriveKek("same-password", salt1);
        byte[] kek2 = cryptoService.deriveKek("same-password", salt2);
        assertFalse(java.util.Arrays.equals(kek1, kek2));
    }

    @Test
    void encryptDecrypt_roundTrip() {
        byte[] key = cryptoService.generateDek();
        byte[] plaintext = "Hello, World!".getBytes();

        String encrypted = cryptoService.encrypt(plaintext, key);
        assertNotNull(encrypted);
        assertNotEquals("Hello, World!", encrypted);

        byte[] decrypted = cryptoService.decrypt(encrypted, key);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void encryptDecrypt_wrongKeyFails() {
        byte[] key1 = cryptoService.generateDek();
        byte[] key2 = cryptoService.generateDek();
        byte[] plaintext = "Secret data".getBytes();

        String encrypted = cryptoService.encrypt(plaintext, key1);

        assertThrows(CryptoService.CryptoException.class, () -> {
            cryptoService.decrypt(encrypted, key2);
        });
    }

    @Test
    void hashMasterPassword_andVerify() {
        String password = "MyStr0ng!Pass";
        String hash = cryptoService.hashMasterPassword(password);

        assertNotNull(hash);
        assertNotEquals(password, hash);
        assertTrue(cryptoService.verifyMasterPassword(password, hash));
        assertFalse(cryptoService.verifyMasterPassword("wrong-password", hash));
    }

    @Test
    void generateDek_returns32Bytes() {
        byte[] dek = cryptoService.generateDek();
        assertEquals(32, dek.length);
    }

    @Test
    void encryptDekDecryptDek_roundTrip() {
        byte[] dek = cryptoService.generateDek();
        byte[] kek = cryptoService.generateDek();

        String encryptedDek = cryptoService.encryptDek(dek, kek);
        byte[] decryptedDek = cryptoService.decryptDek(encryptedDek, kek);

        assertArrayEquals(dek, decryptedDek);
    }

    @Test
    void encryptVerificationString_andVerify() {
        byte[] kek = cryptoService.generateDek();

        String verification = cryptoService.encryptVerificationString(kek);
        assertTrue(cryptoService.verifyKek(verification, kek));

        byte[] wrongKek = cryptoService.generateDek();
        assertFalse(cryptoService.verifyKek(verification, wrongKek));
    }

    @Test
    void clearBytes_zerosOutArray() {
        byte[] data = {1, 2, 3, 4, 5};
        cryptoService.clearBytes(data);
        for (byte b : data) {
            assertEquals(0, b);
        }
    }
}
