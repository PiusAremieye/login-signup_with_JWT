package com.example.jwt.repository;

import com.example.jwt.model.EnumRole;
import com.example.jwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(EnumRole name);
}
