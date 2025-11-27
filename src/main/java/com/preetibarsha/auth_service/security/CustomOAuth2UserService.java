package com.preetibarsha.auth_service.security;

import com.preetibarsha.auth_service.entities.Users;
import com.preetibarsha.auth_service.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepo usersRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        // just return the OAuth2User for Spring Security, Users is handled separately
        return oAuth2User;
    }

    // ✅ Return the actual Users entity
    public Users processOAuth2User(String provider, OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String providerId = oAuth2User.getAttribute("sub");

        Optional<Users> userOptional = usersRepository.findByEmail(email);
        Users user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
        } else {
            // Create new user
            user = new Users();
            user.setEmail(email);
            user.setFullName(name);
            user.setUsername(email); // or generate unique username
            user.setPassword("OAUTH2_USER"); // dummy password for OAuth
            user.setProvider(provider);
            user.setProviderId(providerId);

            usersRepository.save(user);
        }

        return user;
    }
}
