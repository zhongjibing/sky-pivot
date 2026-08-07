package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.SyncLog;
import com.icezhg.sky.pivot.entity.SyncLogId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SyncLogRepository extends JpaRepository<SyncLog, SyncLogId> {

    List<SyncLog> findByUserIdAndClientTimestampGreaterThanOrderByClientTimestampAsc(
            Long userId, Long sinceTimestamp);

    @Query("SELECT s FROM SyncLog s WHERE s.userId = :userId AND s.targetVersion > :sinceVersion ORDER BY s.targetVersion ASC")
    List<SyncLog> findByUserIdAndTargetVersionGreaterThan(
            @Param("userId") Long userId,
            @Param("sinceVersion") long sinceVersion);

    @Query("SELECT s FROM SyncLog s WHERE s.userId = :userId ORDER BY s.serverTimestamp ASC")
    List<SyncLog> findAllByUserId(@Param("userId") Long userId);

    @Modifying
    @Transactional
    @Query(value = "INSERT INTO sync_log_archive SELECT * FROM sync_log WHERE server_timestamp < :beforeTimestamp",
            nativeQuery = true)
    int archiveByServerTimestampBefore(@Param("beforeTimestamp") long beforeTimestamp);

    @Modifying
    @Transactional
    @Query("DELETE FROM SyncLog s WHERE s.serverTimestamp < :beforeTimestamp")
    int deleteByServerTimestampBefore(@Param("beforeTimestamp") long beforeTimestamp);
}
