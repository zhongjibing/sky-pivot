package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.config.properties.TrashProperties;
import com.icezhg.sky.pivot.dto.PasswordDetailResponse;
import com.icezhg.sky.pivot.dto.TrashItemResponse;
import com.icezhg.sky.pivot.entity.Password;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.PasswordRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;

@Service
public class TrashService {

    private final PasswordRepository passwordRepository;
    private final UserRepository userRepository;
    private final CryptoService cryptoService;
    private final int retentionDays;

    public TrashService(PasswordRepository passwordRepository,
                        UserRepository userRepository,
                        CryptoService cryptoService,
                        TrashProperties trashProperties) {
        this.passwordRepository = passwordRepository;
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
        this.retentionDays = trashProperties.getRetentionDays();
    }

    public List<TrashItemResponse> listTrash(Long userId) {
        List<Password> trashed = passwordRepository.findTrashByUserId(userId);
        return trashed.stream()
            .map(p -> {
                long daysInTrash = ChronoUnit.DAYS.between(p.getDeletedAt(), LocalDateTime.now());
                long daysRemaining = Math.max(0, retentionDays - daysInTrash);
                return new TrashItemResponse(p.getId(), p.getTitle(), p.getAccount(), p.getDeletedAt(), daysRemaining);
            })
            .toList();
    }

    @Transactional
    public PasswordDetailResponse viewTrashDetail(Long userId, Long passwordId, String masterPassword) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));

        Password password = passwordRepository.findTrashByIdAndUserId(passwordId, userId)
            .orElseThrow(() -> new RuntimeException("Trashed password not found"));

        byte[] salt = Base64.getDecoder().decode(user.getMasterPasswordSalt());
        byte[] kek = cryptoService.deriveKek(masterPassword, salt);

        if (!cryptoService.verifyKek(user.getKekVerification(), kek)) {
            cryptoService.clearBytes(kek);
            throw new RuntimeException("Wrong master password");
        }

        byte[] dek = cryptoService.decryptDek(user.getEncryptedDek(), kek);
        byte[] plaintext = cryptoService.decrypt(password.getEncryptedPassword(), dek);

        cryptoService.clearBytes(kek);
        cryptoService.clearBytes(dek);

        String passwordPlain = new String(plaintext);
        cryptoService.clearBytes(plaintext);

        return new PasswordDetailResponse(
            password.getId(), password.getTitle(), password.getUrl(),
            password.getAccount(), passwordPlain, password.getNotes(),
            password.getHealthScore(), password.getHealthLevel()
        );
    }

    @Transactional
    public void restorePassword(Long userId, Long passwordId) {
        Password password = passwordRepository.findTrashByIdAndUserId(passwordId, userId)
            .orElseThrow(() -> new RuntimeException("Trashed password not found"));

        password.setDeletedAt(null);
        passwordRepository.save(password);
    }

    @Transactional
    public void permanentlyDelete(Long userId, Long passwordId) {
        Password password = passwordRepository.findTrashByIdAndUserId(passwordId, userId)
            .orElseThrow(() -> new RuntimeException("Trashed password not found"));

        passwordRepository.delete(password);
    }
}
