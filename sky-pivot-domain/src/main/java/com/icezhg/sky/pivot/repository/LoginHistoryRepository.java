package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.LoginHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface LoginHistoryRepository extends JpaRepository<LoginHistory, Long> {

    long countByUserId(Long userId);

    @Modifying
    @Query("DELETE FROM LoginHistory l WHERE l.loginAt < :threshold")
    int deleteByLoginAtBefore(@Param("threshold") LocalDateTime threshold);

    @Modifying
    @Query("DELETE FROM LoginHistory l WHERE l.userId = :userId")
    void deleteByUserId(@Param("userId") Long userId);
}
