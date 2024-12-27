package com.auth.auth_service.config;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.auth.auth_service.entity.User;
import com.auth.auth_service.repo.UserRepo;

@Component
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepo repo;

	public CustomUserDetailsService(UserRepo repo) {
		this.repo = repo;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = repo.findByUsername(username);
		if (user == null) {
			throw new UsernameNotFoundException("User not found: " + username);
		}
		return new CustomUserDetails(user);
	}

}
