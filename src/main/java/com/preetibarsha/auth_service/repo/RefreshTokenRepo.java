package com.preetibarsha.auth_service.repo;

import com.preetibarsha.auth_service.entities.RefreshToken;
import com.preetibarsha.auth_service.entities.Users;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepo extends JpaRepository<RefreshToken,Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUser(Users user);
}
