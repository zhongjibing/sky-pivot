package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.SharedVault;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SharedVaultRepository extends JpaRepository<SharedVault, Long> {

    List<SharedVault> findByOwnerId(Long ownerId);
}
