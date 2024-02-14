package com.ohgiraffers.security.auth.user.repository;

import com.ohgiraffers.security.auth.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByUserId(String id);
}
