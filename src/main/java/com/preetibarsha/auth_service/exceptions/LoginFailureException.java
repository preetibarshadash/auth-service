package com.preetibarsha.auth_service.exceptions;

public class LoginFailureException extends Exception {
    public LoginFailureException(String message) {
        super(message);
    }
}
