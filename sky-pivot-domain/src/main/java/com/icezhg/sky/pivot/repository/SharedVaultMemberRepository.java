package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.SharedVaultMember;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SharedVaultMemberRepository extends JpaRepository<SharedVaultMember, Long> {

    List<SharedVaultMember> findByVaultId(String vaultId);

    List<SharedVaultMember> findByUserId(Long userId);
}
