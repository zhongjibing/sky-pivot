package com.icezhg.sky.pivot.repository;

import com.icezhg.sky.pivot.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByRecoveryKeyHash(String recoveryKeyHash);

    List<User> findByStatus(Integer status);
}
