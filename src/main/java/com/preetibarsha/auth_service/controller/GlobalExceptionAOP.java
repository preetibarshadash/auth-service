package com.preetibarsha.auth_service.controller;

import com.preetibarsha.auth_service.exceptions.LoginFailureException;
import com.preetibarsha.auth_service.exceptions.RegistrationFailureException;
import com.preetibarsha.auth_service.exceptions.UserNotFoundException;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Aspect
@Component
public class GlobalExceptionAOP {

    @Around("execution(* com.preetibarsha.auth_service..controller..*(..))")
    public Object handleControllerExceptions(ProceedingJoinPoint joinPoint) throws Throwable {
        try {
            return joinPoint.proceed();
        } catch (LoginFailureException | RegistrationFailureException ex) {
            return buildErrorResponse(ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (UserNotFoundException ex) {
            return buildErrorResponse(ex.getMessage(), HttpStatus.NOT_FOUND);
        } catch (Exception ex) {
            return buildErrorResponse("Internal Server Error: " + ex.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private ResponseEntity<Map<String, Object>> buildErrorResponse(String message, HttpStatus status) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        return new ResponseEntity<>(body, status);
    }
}
