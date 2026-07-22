package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.Device;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DeviceRepository extends JpaRepository<Device, Long> {

    List<Device> findByUserId(Long userId);

    Optional<Device> findByUserIdAndDeviceId(Long userId, String deviceId);

    List<Device> findByUserIdAndAuthorizedTrueAndRevokedFalse(Long userId);
}
