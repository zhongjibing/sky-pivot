package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.VaultItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface VaultItemRepository extends JpaRepository<VaultItem, Long> {

    List<VaultItem> findByUserId(Long userId);

    Optional<VaultItem> findByUserIdAndItemId(Long userId, String itemId);

    Optional<VaultItem> findByUserIdAndId(Long userId, Long id);

    @Query("SELECT v FROM VaultItem v WHERE v.userId = :userId AND v.deletedAt IS NOT NULL ORDER BY v.deletedAt DESC")
    List<VaultItem> findTrashByUserId(@Param("userId") Long userId);

    @Query("SELECT v FROM VaultItem v WHERE v.id = :id AND v.userId = :userId AND v.deletedAt IS NOT NULL")
    Optional<VaultItem> findTrashByIdAndUserId(@Param("id") Long id, @Param("userId") Long userId);

    @Modifying
    @Query("DELETE FROM VaultItem v WHERE v.deletedAt IS NOT NULL AND v.deletedAt < :threshold")
    int deletePermanentlyByDeletedAtBefore(@Param("threshold") LocalDateTime threshold);

    List<VaultItem> findByUserIdAndDeletedAtIsNull(Long userId);
}
