package com.auth.auth_service.model;

import lombok.Data;

@Data
public class UserModel {

	private Long id;

	private String email;

	private String username;

	private String password;

	private String role;
}
