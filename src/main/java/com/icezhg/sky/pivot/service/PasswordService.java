package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.PasswordCreateRequest;
import com.icezhg.sky.pivot.dto.PasswordCreateResponse;
import com.icezhg.sky.pivot.dto.PasswordDetailResponse;
import com.icezhg.sky.pivot.dto.PasswordListResponse;
import com.icezhg.sky.pivot.dto.PasswordUpdateRequest;
import com.icezhg.sky.pivot.entity.Password;
import com.icezhg.sky.pivot.entity.SyncVersion;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.PasswordRepository;
import com.icezhg.sky.pivot.repository.SyncVersionRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import com.icezhg.sky.pivot.security.TemporaryTokenService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;

@Service
public class PasswordService {

    private final PasswordRepository passwordRepository;
    private final UserRepository userRepository;
    private final SyncVersionRepository syncVersionRepository;
    private final CryptoService cryptoService;
    private final HealthService healthService;
    private final TemporaryTokenService temporaryTokenService;

    public PasswordService(PasswordRepository passwordRepository,
                           UserRepository userRepository,
                           SyncVersionRepository syncVersionRepository,
                           CryptoService cryptoService,
                           HealthService healthService,
                           TemporaryTokenService temporaryTokenService) {
        this.passwordRepository = passwordRepository;
        this.userRepository = userRepository;
        this.syncVersionRepository = syncVersionRepository;
        this.cryptoService = cryptoService;
        this.healthService = healthService;
        this.temporaryTokenService = temporaryTokenService;
    }

    public Page<PasswordListResponse> listPasswords(Long userId, String search, String sortBy, String sortOrder, int page, int size) {
        Sort sort = "asc".equalsIgnoreCase(sortOrder) ? Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(page, size, sort);

        Page<Password> passwords;
        if (search != null && !search.isBlank()) {
            passwords = passwordRepository.searchByUserId(userId, search, pageable);
        } else {
            passwords = passwordRepository.findByUserId(userId, pageable);
        }

        return passwords.map(p -> new PasswordListResponse(
                p.getId(), p.getTitle(), p.getUrl(), p.getAccount(), p.getHealthLevel(), p.getUpdatedAt()
        ));
    }

    @Transactional
    public PasswordDetailResponse viewPassword(Long userId, Long passwordId, String masterPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Password password = passwordRepository.findByIdAndUserId(passwordId, userId)
                .orElseThrow(() -> new RuntimeException("Password not found"));

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
    public PasswordCreateResponse createPassword(Long userId, PasswordCreateRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        byte[] salt = Base64.getDecoder().decode(user.getMasterPasswordSalt());
        byte[] kek = cryptoService.deriveKek("setup", salt);
        byte[] dek = cryptoService.decryptDek(user.getEncryptedDek(), kek);

        HealthService.HealthResult health = healthService.checkHealth(request.password());

        String encryptedPassword = cryptoService.encrypt(request.password().getBytes(), dek);

        cryptoService.clearBytes(kek);
        cryptoService.clearBytes(dek);

        Password password = new Password();
        password.setUserId(userId);
        password.setTitle(request.title());
        password.setUrl(request.url());
        password.setAccount(request.account());
        password.setEncryptedPassword(encryptedPassword);
        password.setNotes(request.notes());
        password.setHealthScore(health.score());
        password.setHealthLevel(health.level());

        password = passwordRepository.save(password);
        incrementSyncVersion(userId);

        return new PasswordCreateResponse(password.getId(), health.score(), health.level());
    }

    @Transactional
    public void updatePassword(Long userId, Long passwordId, PasswordUpdateRequest request, String masterPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Password password = passwordRepository.findByIdAndUserId(passwordId, userId)
                .orElseThrow(() -> new RuntimeException("Password not found"));

        byte[] salt = Base64.getDecoder().decode(user.getMasterPasswordSalt());
        byte[] kek = cryptoService.deriveKek(masterPassword, salt);

        if (!cryptoService.verifyKek(user.getKekVerification(), kek)) {
            cryptoService.clearBytes(kek);
            throw new RuntimeException("Wrong master password");
        }

        byte[] dek = cryptoService.decryptDek(user.getEncryptedDek(), kek);

        HealthService.HealthResult health = healthService.checkHealth(request.password());
        String encryptedPassword = cryptoService.encrypt(request.password().getBytes(), dek);

        cryptoService.clearBytes(kek);
        cryptoService.clearBytes(dek);

        password.setUrl(request.url());
        password.setAccount(request.account());
        password.setEncryptedPassword(encryptedPassword);
        password.setNotes(request.notes());
        password.setHealthScore(health.score());
        password.setHealthLevel(health.level());

        passwordRepository.save(password);
        incrementSyncVersion(userId);
    }

    @Transactional
    public void softDeletePassword(Long userId, Long passwordId) {
        Password password = passwordRepository.findByIdAndUserId(passwordId, userId)
                .orElseThrow(() -> new RuntimeException("Password not found"));

        password.setDeletedAt(java.time.LocalDateTime.now());
        passwordRepository.save(password);
        incrementSyncVersion(userId);
    }

    private void incrementSyncVersion(Long userId) {
        SyncVersion syncVersion = syncVersionRepository.findByUserId(userId)
                .orElseGet(() -> {
                    SyncVersion sv = new SyncVersion();
                    sv.setUserId(userId);
                    sv.setVersion(0L);
                    return sv;
                });
        syncVersion.incrementVersion();
        syncVersionRepository.save(syncVersion);
    }
}
