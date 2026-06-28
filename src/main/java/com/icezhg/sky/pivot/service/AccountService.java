package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.AccountDeletePreviewResponse;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.LoginHistoryRepository;
import com.icezhg.sky.pivot.repository.PasswordRepository;
import com.icezhg.sky.pivot.repository.SyncVersionRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccountService {

    private final UserRepository userRepository;
    private final PasswordRepository passwordRepository;
    private final SyncVersionRepository syncVersionRepository;
    private final LoginHistoryRepository loginHistoryRepository;

    public AccountService(UserRepository userRepository,
                          PasswordRepository passwordRepository,
                          SyncVersionRepository syncVersionRepository,
                          LoginHistoryRepository loginHistoryRepository) {
        this.userRepository = userRepository;
        this.passwordRepository = passwordRepository;
        this.syncVersionRepository = syncVersionRepository;
        this.loginHistoryRepository = loginHistoryRepository;
    }

    public AccountDeletePreviewResponse previewDeletion(Long userId) {
        long totalPasswords = passwordRepository.findByUserId(userId, org.springframework.data.domain.Pageable.unpaged()).getTotalElements();
        long trashedPasswords = passwordRepository.findTrashByUserId(userId).size();
        long loginHistoryRecords = loginHistoryRepository.count();

        return new AccountDeletePreviewResponse(totalPasswords, trashedPasswords, loginHistoryRecords);
    }

    @Transactional
    public void deleteAccount(Long userId) {
        passwordRepository.deleteByUserId(userId);
        syncVersionRepository.deleteByUserId(userId);
        loginHistoryRepository.deleteByUserId(userId);

        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));
        user.setStatus(2);
        userRepository.save(user);
    }
}
