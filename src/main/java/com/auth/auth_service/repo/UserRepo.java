package com.auth.auth_service.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.auth.auth_service.entity.User;

@Repository
public interface UserRepo extends JpaRepository<User, Long> {

	User findByEmail(String email);

	User findByUsername(String username);

}
