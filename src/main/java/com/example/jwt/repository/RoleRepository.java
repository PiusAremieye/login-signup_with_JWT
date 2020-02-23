package com.example.jwt.repository;

import com.example.jwt.model.EnumRole;
import com.example.jwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(EnumRole name);
    Optional<Role> existsByName(EnumRole name);
}
