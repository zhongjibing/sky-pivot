package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.AuditLog;
import com.icezhg.sky.pivot.entity.AuditLogId;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, AuditLogId> {

    List<AuditLog> findByUserIdOrderByCreatedAtDesc(Long userId);

    Page<AuditLog> findByUserId(Long userId, Pageable pageable);

    List<AuditLog> findByUserIdAndCreatedAtBetween(Long userId, LocalDateTime start, LocalDateTime end);
}
