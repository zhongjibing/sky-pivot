package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.VaultItemCreateRequest;
import com.icezhg.sky.pivot.dto.VaultItemResponse;
import com.icezhg.sky.pivot.dto.VaultItemUpdateRequest;
import com.icezhg.sky.pivot.dto.VaultListResponse;
import com.icezhg.sky.pivot.dto.VaultTrashItemResponse;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.entity.VaultItem;
import com.icezhg.sky.pivot.exception.VaultException;
import com.icezhg.sky.pivot.repository.UserRepository;
import com.icezhg.sky.pivot.repository.VaultItemRepository;

import java.time.LocalDateTime;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

@Service
public class VaultService {

    private static final Logger log = LoggerFactory.getLogger(VaultService.class);

    private final VaultItemRepository vaultItemRepository;
    private final UserRepository userRepository;
    private final SyncService syncService;
    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    public VaultService(VaultItemRepository vaultItemRepository,
                        UserRepository userRepository,
                        SyncService syncService) {
        this.vaultItemRepository = vaultItemRepository;
        this.userRepository = userRepository;
        this.syncService = syncService;
    }

    @Transactional
    public VaultItemResponse create(Long userId, String deviceId, VaultItemCreateRequest request) {
        validateJsonBlob(request.encryptedBlob());

        if (vaultItemRepository.findByUserIdAndItemId(userId, request.itemId()).isPresent()) {
            throw new VaultException("Item with this itemId already exists");
        }

        User user = getUser(userId);
        long newVersion = user.getSyncVersion() + 1;

        VaultItem item = new VaultItem();
        item.setUserId(userId);
        item.setItemId(request.itemId());
        item.setEncryptedBlob(request.encryptedBlob());
        item.setVersion(newVersion);
        item.setCreatedAt(LocalDateTime.now());
        item.setUpdatedAt(LocalDateTime.now());

        vaultItemRepository.save(item);

        user.setSyncVersion(newVersion);
        userRepository.save(user);

        syncService.recordOperation(userId, deviceId, "CREATE", request.itemId(), "VAULT_ITEM", newVersion);

        log.debug("Vault item created: userId={}, itemId={}, version={}", userId, request.itemId(), newVersion);

        return toResponse(item);
    }

    public VaultItemResponse get(Long userId, String itemId) {
        VaultItem item = vaultItemRepository.findByUserIdAndItemId(userId, itemId)
                .orElseThrow(() -> new VaultException("Vault item not found"));
        return toResponse(item);
    }

    public VaultListResponse list(Long userId, Long sinceVersion) {
        User user = getUser(userId);
        long currentSyncVersion = user.getSyncVersion();

        List<VaultItem> items;
        if (sinceVersion != null && sinceVersion >= 0) {
            items = vaultItemRepository.findByUserIdAndVersionGreaterThan(userId, sinceVersion);
        } else {
            items = vaultItemRepository.findByUserIdAndDeletedAtIsNull(userId);
        }

        List<VaultItemResponse> itemResponses = items.stream()
                .map(VaultService::toResponse)
                .toList();

        return new VaultListResponse(itemResponses, currentSyncVersion);
    }

    @Transactional
    public VaultItemResponse update(Long userId, String deviceId, String itemId, VaultItemUpdateRequest request) {
        validateJsonBlob(request.encryptedBlob());

        VaultItem item = vaultItemRepository.findByUserIdAndItemId(userId, itemId)
                .orElseThrow(() -> new VaultException("Vault item not found"));

        if (!item.getVersion().equals(request.version())) {
            throw new VaultException("Version conflict: item has been modified since last read");
        }

        User user = getUser(userId);
        long newVersion = user.getSyncVersion() + 1;

        item.setEncryptedBlob(request.encryptedBlob());
        item.setVersion(newVersion);
        item.setUpdatedAt(LocalDateTime.now());

        vaultItemRepository.save(item);

        user.setSyncVersion(newVersion);
        userRepository.save(user);

        syncService.recordOperation(userId, deviceId, "UPDATE", itemId, "VAULT_ITEM", newVersion);

        log.debug("Vault item updated: userId={}, itemId={}, version={}", userId, itemId, newVersion);

        return toResponse(item);
    }

    @Transactional
    public void delete(Long userId, String deviceId, String itemId) {
        VaultItem item = vaultItemRepository.findByUserIdAndItemId(userId, itemId)
                .orElseThrow(() -> new VaultException("Vault item not found"));

        User user = getUser(userId);
        long newVersion = user.getSyncVersion() + 1;

        item.setDeletedAt(LocalDateTime.now());
        item.setVersion(newVersion);
        item.setUpdatedAt(LocalDateTime.now());

        vaultItemRepository.save(item);

        user.setSyncVersion(newVersion);
        userRepository.save(user);

        syncService.recordOperation(userId, deviceId, "DELETE", itemId, "VAULT_ITEM", newVersion);

        log.debug("Vault item soft-deleted: userId={}, itemId={}, version={}", userId, itemId, newVersion);
    }

    public List<VaultTrashItemResponse> listTrash(Long userId) {
        List<VaultItem> trashItems = vaultItemRepository.findTrashByUserId(userId);
        return trashItems.stream()
                .map(VaultService::toTrashResponse)
                .toList();
    }

    @Transactional
    public void restoreTrash(Long userId, String deviceId, String itemId) {
        VaultItem item = vaultItemRepository.findByUserIdAndItemIdAnyState(userId, itemId)
                .orElseThrow(() -> new VaultException("Trash item not found"));

        if (item.getDeletedAt() == null) {
            throw new VaultException("Item is not in trash");
        }

        User user = getUser(userId);
        long newVersion = user.getSyncVersion() + 1;

        item.setDeletedAt(null);
        item.setVersion(newVersion);
        item.setUpdatedAt(LocalDateTime.now());

        vaultItemRepository.save(item);

        user.setSyncVersion(newVersion);
        userRepository.save(user);

        syncService.recordOperation(userId, deviceId, "RESTORE", itemId, "VAULT_ITEM", newVersion);

        log.debug("Vault item restored from trash: userId={}, itemId={}, version={}", userId, itemId, newVersion);
    }

    @Transactional
    public void permanentDelete(Long userId, String itemId) {
        VaultItem item = vaultItemRepository.findByUserIdAndItemIdAnyState(userId, itemId)
                .orElseThrow(() -> new VaultException("Trash item not found"));

        if (item.getDeletedAt() == null) {
            throw new VaultException("Item is not in trash: use DELETE to soft-delete first");
        }

        vaultItemRepository.delete(item);

        log.debug("Vault item permanently deleted: userId={}, itemId={}", userId, itemId);
    }

    private void validateJsonBlob(String blob) {
        if (blob == null || blob.isBlank()) {
            throw new VaultException("encrypted_blob must not be empty");
        }
        try {
            jsonMapper.readTree(blob);
        } catch (Exception e) {
            throw new VaultException("encrypted_blob must be valid JSON");
        }
    }

    private User getUser(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new VaultException("User not found"));
    }

    private static VaultItemResponse toResponse(VaultItem item) {
        return new VaultItemResponse(
                item.getId(),
                item.getItemId(),
                item.getEncryptedBlob(),
                item.getVersion(),
                item.getCreatedAt(),
                item.getUpdatedAt()
        );
    }

    private static VaultTrashItemResponse toTrashResponse(VaultItem item) {
        return new VaultTrashItemResponse(
                item.getId(),
                item.getItemId(),
                item.getEncryptedBlob(),
                item.getVersion(),
                item.getCreatedAt(),
                item.getUpdatedAt(),
                item.getDeletedAt()
        );
    }
}
