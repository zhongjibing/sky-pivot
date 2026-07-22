package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.SyncVersion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SyncVersionRepository extends JpaRepository<SyncVersion, Long> {

    Optional<SyncVersion> findByUserId(Long userId);

    @Modifying
    @Query("DELETE FROM SyncVersion s WHERE s.userId = :userId")
    void deleteByUserId(@Param("userId") Long userId);
}
