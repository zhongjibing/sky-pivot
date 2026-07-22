package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.config.properties.CryptoProperties;
import com.icezhg.sky.pivot.exception.CryptoException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

@Service
public class CryptoService {

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String VERIFICATION_PLAIN = "VERIFIED";

    private final int pbkdf2Iterations;
    private final int pbkdf2KeyLength;
    private final int bcryptCost;
    private final SecureRandom secureRandom = new SecureRandom();

    public CryptoService(CryptoProperties cryptoProperties) {
        this.pbkdf2Iterations = cryptoProperties.getPbkdf2Iterations();
        this.pbkdf2KeyLength = cryptoProperties.getPbkdf2KeyLength();
        this.bcryptCost = cryptoProperties.getBcryptCost();
    }

    public byte[] generateSalt(int length) {
        byte[] salt = new byte[length];
        secureRandom.nextBytes(salt);
        return salt;
    }

    public byte[] deriveKek(String masterPassword, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt, pbkdf2Iterations, pbkdf2KeyLength);
            SecretKey key = factory.generateSecret(spec);
            return key.getEncoded();
        } catch (Exception e) {
            throw new CryptoException("Failed to derive KEK", e);
        }
    }

    public byte[] deriveBiometricKey(String biometricToken, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            KeySpec spec = new PBEKeySpec(biometricToken.toCharArray(), salt, 100000, pbkdf2KeyLength);
            SecretKey key = factory.generateSecret(spec);
            return key.getEncoded();
        } catch (Exception e) {
            throw new CryptoException("Failed to derive biometric key", e);
        }
    }

    public String encrypt(byte[] plaintext, byte[] key) {
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_GCM);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    public byte[] decrypt(String encrypted, byte[] key) {
        try {
            byte[] combined = Base64.getDecoder().decode(encrypted);

            byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(combined, GCM_IV_LENGTH, combined.length);

            Cipher cipher = Cipher.getInstance(AES_GCM);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    public String hashMasterPassword(String masterPassword) {
        return BCrypt.hashpw(masterPassword, BCrypt.gensalt(bcryptCost));
    }

    public boolean verifyMasterPassword(String masterPassword, String hash) {
        try {
            return BCrypt.checkpw(masterPassword, hash);
        } catch (Exception e) {
            return false;
        }
    }

    public byte[] generateDek() {
        byte[] dek = new byte[32];
        secureRandom.nextBytes(dek);
        return dek;
    }

    public String encryptDek(byte[] dek, byte[] kek) {
        return encrypt(dek, kek);
    }

    public byte[] decryptDek(String encryptedDek, byte[] kek) {
        return decrypt(encryptedDek, kek);
    }

    public String encryptVerificationString(byte[] kek) {
        return encrypt(VERIFICATION_PLAIN.getBytes(), kek);
    }

    public boolean verifyKek(String encryptedVerification, byte[] kek) {
        try {
            byte[] decrypted = decrypt(encryptedVerification, kek);
            String result = new String(decrypted);
            return VERIFICATION_PLAIN.equals(result);
        } catch (Exception e) {
            return false;
        }
    }

    public void clearBytes(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
}
