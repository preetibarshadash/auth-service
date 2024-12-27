package com.auth.auth_service.service;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth.auth_service.config.JwtConfig;
import com.auth.auth_service.entity.User;
import com.auth.auth_service.model.UserModel;
import com.auth.auth_service.repo.UserRepo;

@Service
public class UserService {

	@Autowired
	private ModelMapper mapper;

	@Autowired
	private UserRepo repo;

	@Autowired
	private BCryptPasswordEncoder encoder;

	private final AuthenticationManager authManager;

	private final JwtConfig jwt;

	public UserService(AuthenticationManager authManager, JwtConfig jwt) {
		this.authManager = authManager;
		this.jwt = jwt;
	}

	public ResponseEntity<UserModel> registerUser(UserModel model) {
		User user = mapper.map(model, User.class);
		String password = model.getPassword();
		user.setPassword(encoder.encode(password));
		User save = repo.save(user);
		UserModel response = mapper.map(save, UserModel.class);
		return new ResponseEntity<UserModel>(response, HttpStatus.CREATED);

	}

	public ResponseEntity<?> resetPassword(String email, String newPassword) {
		User user = repo.findByEmail(email);
		if (user == null)
			return new ResponseEntity<>("No user found!", HttpStatus.NO_CONTENT);
		user.setPassword(encoder.encode(newPassword));
		repo.save(user);
		return new ResponseEntity<>("Password set successfully!", HttpStatus.OK);
	}

	public String validateUser(UserModel model) {
		User user = repo.findByUsername(model.getUsername());
		System.out.println(user);
		if (user == null)
			return "No user found!";

		if (!encoder.matches(model.getPassword(), user.getPassword())) {
			return "Invalid credentials";
		}
		Authentication authentication = authManager
				.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), model.getPassword()));
		if (authentication.isAuthenticated()) {
			return jwt.generateToken(user);
		}

		return "failed";
	}
}
