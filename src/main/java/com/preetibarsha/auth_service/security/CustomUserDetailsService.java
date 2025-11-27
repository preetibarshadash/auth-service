package com.preetibarsha.auth_service.security;

import com.preetibarsha.auth_service.entities.Users;
import com.preetibarsha.auth_service.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepo usersRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users u = usersRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        // return a minimal UserDetails (roles can be added later)
        return org.springframework.security.core.userdetails.User
                .withUsername(u.getUsername())
                .password(u.getPassword() == null ? "" : u.getPassword())
                .authorities("ROLE_USER")
                .build();
    }
}
