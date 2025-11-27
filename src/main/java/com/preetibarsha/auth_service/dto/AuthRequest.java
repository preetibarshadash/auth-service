package com.preetibarsha.auth_service.dto;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthRequest {
        private String username;
        private String password;
        private Boolean remember; // optional, default false
}
