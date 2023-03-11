package io.rockettech.auth.repositories;


import org.springframework.data.jpa.repository.JpaRepository;

import io.rockettech.auth.entities.AuthUser;

import java.util.Optional;

public interface UserRepository extends JpaRepository<AuthUser, Long> {

    Optional<AuthUser> findByLogin(String login);
}
