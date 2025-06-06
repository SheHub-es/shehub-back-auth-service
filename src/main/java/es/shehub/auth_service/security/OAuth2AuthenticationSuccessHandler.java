package es.shehub.auth_service.security;

import java.io.IOException;

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import es.shehub.auth_service.mappers.UserMapper;
import es.shehub.auth_service.models.dtos.GoogleUserDTO;
import es.shehub.auth_service.models.dtos.UserDTO;
import es.shehub.auth_service.models.entities.User;
import es.shehub.auth_service.repositories.UserRepository;
import es.shehub.auth_service.security.jwt.JwtUtil;
import es.shehub.auth_service.services.UserService;
import es.shehub.auth_service.utils.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Handles successful OAuth2 authentication events.
 * This handler processes the OAuth2 login success by:
 * Extracting user information from the OAuth2 authentication token.
 * Checking if the user already exists in the database; if not, registering a
 * new user.
 * Verifying if the user is approved to access the system.
 * Generating JWT access and refresh tokens.
 * Setting the tokens as HTTP cookies in the response.
 * Redirecting the user to the frontend application (dashboard or registration
 * page depending on profile completion).
 * 
 * If the email is not found in the OAuth2 response or the user is not approved,
 * appropriate responses or redirects are sent.
 */
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final UserMapper userMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        SecurityContextHolder.getContext().setAuthentication(authentication);

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        if (email == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Email not found in OAuth2 response.");
            return;
        }

        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;

        if (userOptional.isEmpty()) {
            GoogleUserDTO googleUserDTO = new GoogleUserDTO();
            googleUserDTO.setEmail(email);
            googleUserDTO.setFirstName(oAuth2User.getAttribute("given_name"));
            googleUserDTO.setLastName(oAuth2User.getAttribute("family_name"));

            user = userService.registerGoogleUser(googleUserDTO);
        } else {
            user = userOptional.get();
        }

        // If not approved, redirect to SPECIAL FRONTEND PAGE that shows message "Can't
        // login. Please, wait for the approval by the SheHub team"
        if (!"APPROVED".equalsIgnoreCase(user.getStatus())) {
            response.sendRedirect("http://localhost:5173");
            return;
        }

        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        response.addHeader("Set-Cookie", CookieUtil.createAccessTokenCookie(accessToken).toString());
        response.addHeader("Set-Cookie", CookieUtil.createRefreshTokenCookie(refreshToken).toString());

        UserDTO dto = userMapper.toUserDTO(user);

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        new ObjectMapper().writeValue(response.getWriter(), dto);

    }
}
