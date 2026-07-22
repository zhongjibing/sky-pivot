package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.SyncLog;
import com.icezhg.sky.pivot.entity.SyncLogId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SyncLogRepository extends JpaRepository<SyncLog, SyncLogId> {

    List<SyncLog> findByUserIdAndClientTimestampGreaterThanOrderByClientTimestampAsc(Long userId, Long sinceTimestamp);
}
