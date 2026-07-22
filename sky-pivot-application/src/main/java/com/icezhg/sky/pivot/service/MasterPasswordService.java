package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.exception.DecryptionFailedException;
import com.icezhg.sky.pivot.exception.MasterPasswordAlreadySetException;
import com.icezhg.sky.pivot.exception.MasterPasswordNotSetException;
import com.icezhg.sky.pivot.exception.MasterPasswordUserNotFoundException;
import com.icezhg.sky.pivot.exception.SamePasswordException;
import com.icezhg.sky.pivot.exception.WrongMasterPasswordException;
import com.icezhg.sky.pivot.repository.UserRepository;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Base64;

@Service
public class MasterPasswordService {

    private final UserRepository userRepository;
    private final CryptoService cryptoService;

    public MasterPasswordService(UserRepository userRepository,
                                  CryptoService cryptoService) {
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
    }

    @Transactional
    public void setupMasterPassword(String masterPassword) {
        Long userId = JwtAuthContext.getUserId();
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new MasterPasswordUserNotFoundException(userId));

        if (user.isMasterPasswordSet()) {
            throw new MasterPasswordAlreadySetException();
        }

        byte[] salt = cryptoService.generateSalt(16);
        byte[] kek = cryptoService.deriveKek(masterPassword, salt);
        byte[] dek = cryptoService.generateDek();

        String encryptedDek = cryptoService.encryptDek(dek, kek);
        String kekVerification = cryptoService.encryptVerificationString(kek);
        String passwordHash = cryptoService.hashMasterPassword(masterPassword);

        user.setMasterPasswordSalt(Base64.getEncoder().encodeToString(salt));
        user.setMasterPasswordHash(passwordHash);
        user.setEncryptedDek(encryptedDek);
        user.setKekVerification(kekVerification);
        user.setLastMasterPasswordVerifiedAt(LocalDateTime.now());

        userRepository.save(user);

        cryptoService.clearBytes(kek);
        cryptoService.clearBytes(dek);
    }

    @Transactional
    public void verifyMasterPassword(String masterPassword) {
        Long userId = JwtAuthContext.getUserId();
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new MasterPasswordUserNotFoundException(userId));

        if (!user.isMasterPasswordSet()) {
            throw new MasterPasswordNotSetException();
        }

        if (!cryptoService.verifyMasterPassword(masterPassword, user.getMasterPasswordHash())) {
            cryptoService.clearBytes(masterPassword.getBytes());
            throw new WrongMasterPasswordException();
        }

        user.setLastMasterPasswordVerifiedAt(LocalDateTime.now());
        userRepository.save(user);
    }

    @Transactional
    public void changeMasterPassword(String currentPassword, String newPassword) {
        Long userId = JwtAuthContext.getUserId();
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new MasterPasswordUserNotFoundException(userId));

        if (!user.isMasterPasswordSet()) {
            throw new MasterPasswordNotSetException();
        }

        if (!cryptoService.verifyMasterPassword(currentPassword, user.getMasterPasswordHash())) {
            throw new WrongMasterPasswordException();
        }

        if (currentPassword.equals(newPassword)) {
            throw new SamePasswordException();
        }

        byte[] oldSalt = Base64.getDecoder().decode(user.getMasterPasswordSalt());
        byte[] oldKek = cryptoService.deriveKek(currentPassword, oldSalt);

        byte[] dek;
        try {
            dek = cryptoService.decryptDek(user.getEncryptedDek(), oldKek);
        } catch (Exception e) {
            throw new DecryptionFailedException();
        }

        byte[] newSalt = cryptoService.generateSalt(16);
        byte[] newKek = cryptoService.deriveKek(newPassword, newSalt);

        String newEncryptedDek = cryptoService.encryptDek(dek, newKek);
        String newKekVerification = cryptoService.encryptVerificationString(newKek);
        String newPasswordHash = cryptoService.hashMasterPassword(newPassword);

        user.setMasterPasswordSalt(Base64.getEncoder().encodeToString(newSalt));
        user.setMasterPasswordHash(newPasswordHash);
        user.setEncryptedDek(newEncryptedDek);
        user.setKekVerification(newKekVerification);
        user.setLastMasterPasswordVerifiedAt(LocalDateTime.now());

        if (user.getBiometricTokenSalt() != null && user.getEncryptedKekForBiometric() != null) {
            byte[] biometricSalt = Base64.getDecoder().decode(user.getBiometricTokenSalt());
            String biometricToken = "biometric-channel-token-" + userId;
            byte[] biometricKey = cryptoService.deriveBiometricKey(biometricToken, biometricSalt);
            String newEncryptedKekForBiometric = cryptoService.encrypt(newKek, biometricKey);
            user.setEncryptedKekForBiometric(newEncryptedKekForBiometric);
            cryptoService.clearBytes(biometricKey);
        }

        userRepository.save(user);

        cryptoService.clearBytes(oldKek);
        cryptoService.clearBytes(newKek);
        cryptoService.clearBytes(dek);
    }

    public boolean isMasterPasswordSet() {
        Long userId = JwtAuthContext.getUserId();
        return userRepository.findById(userId)
            .map(User::isMasterPasswordSet)
            .orElse(false);
    }

    @Transactional
    public void bindBiometric(String masterPassword) {
        Long userId = JwtAuthContext.getUserId();
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new MasterPasswordUserNotFoundException(userId));

        if (!cryptoService.verifyMasterPassword(masterPassword, user.getMasterPasswordHash())) {
            throw new WrongMasterPasswordException();
        }

        byte[] salt = Base64.getDecoder().decode(user.getMasterPasswordSalt());
        byte[] kek = cryptoService.deriveKek(masterPassword, salt);

        byte[] biometricSalt = cryptoService.generateSalt(16);
        String biometricToken = "biometric-channel-token-" + userId;
        byte[] biometricKey = cryptoService.deriveBiometricKey(biometricToken, biometricSalt);

        String encryptedKekForBiometric = cryptoService.encrypt(kek, biometricKey);

        user.setBiometricTokenSalt(Base64.getEncoder().encodeToString(biometricSalt));
        user.setEncryptedKekForBiometric(encryptedKekForBiometric);
        userRepository.save(user);

        cryptoService.clearBytes(kek);
        cryptoService.clearBytes(biometricKey);
    }
}
