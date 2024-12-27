package com.auth.auth_service.controller;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.auth.auth_service.model.UserModel;
import com.auth.auth_service.service.UserService;

@RestController
@RequestMapping("/user")
public class UserController {

	@Autowired
	private UserService service;

	@PostMapping("/register")
	ResponseEntity<?> registerUser(@RequestBody UserModel model) {
		return service.registerUser(model);
	}

	@PutMapping("/resetPassword")
	ResponseEntity<?> resetPassword(@RequestParam String email, @RequestParam String newPassword) {
		return service.resetPassword(email, newPassword);
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody UserModel user) {
		String validatedUser = service.validateUser(user);
		return ResponseEntity.ok(Collections.singletonMap("response", validatedUser));
	}
	
	@GetMapping
	public String welcome() {
		return "welcome";
	}
}
