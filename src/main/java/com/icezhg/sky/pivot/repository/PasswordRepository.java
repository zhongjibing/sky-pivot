package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.Password;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface PasswordRepository extends JpaRepository<Password, Long> {

    Page<Password> findByUserId(Long userId, Pageable pageable);

    @Query("SELECT p FROM Password p WHERE p.userId = :userId AND " +
           "(LOWER(p.title) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(p.account) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(p.url) LIKE LOWER(CONCAT('%', :search, '%')))")
    Page<Password> searchByUserId(@Param("userId") Long userId,
                                   @Param("search") String search,
                                   Pageable pageable);

    Optional<Password> findByIdAndUserId(Long id, Long userId);

    @Query("SELECT p FROM Password p WHERE p.userId = :userId AND p.deletedAt IS NOT NULL ORDER BY p.deletedAt DESC")
    List<Password> findTrashByUserId(@Param("userId") Long userId);

    @Query("SELECT p FROM Password p WHERE p.id = :id AND p.userId = :userId AND p.deletedAt IS NOT NULL")
    Optional<Password> findTrashByIdAndUserId(@Param("id") Long id, @Param("userId") Long userId);

    @Modifying
    @Query("DELETE FROM Password p WHERE p.deletedAt < :threshold")
    int deleteByDeletedAtBefore(@Param("threshold") LocalDateTime threshold);

    @Modifying
    @Query("DELETE FROM Password p WHERE p.userId = :userId")
    int deleteByUserId(@Param("userId") Long userId);

    List<Password> findByUserIdAndHealthLevel(Long userId, String healthLevel);

    @Query("SELECT COUNT(p) FROM Password p WHERE p.userId = :userId AND p.healthLevel = :level AND p.deletedAt IS NULL")
    long countByUserIdAndHealthLevel(@Param("userId") Long userId, @Param("level") String level);

    List<Password> findByUserIdAndUpdatedAtAfter(Long userId, LocalDateTime since);
}
