package es.shehub.auth_service.security;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import es.shehub.auth_service.config.ApiPaths;
import es.shehub.auth_service.mappers.UserMapper;
import es.shehub.auth_service.models.dtos.GoogleUserDTO;
import es.shehub.auth_service.models.dtos.UserCreatedDTO;
import es.shehub.auth_service.models.dtos.UserRegisterRequestDTO;
import es.shehub.auth_service.models.entities.User;
import es.shehub.auth_service.repositories.UserRepository;
import es.shehub.auth_service.security.jwt.JwtUtil;
import es.shehub.auth_service.services.UserService;
import es.shehub.auth_service.utils.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final UserService userService;
    private final UserMapper userMapper;
    private final JwtUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        SecurityContextHolder.getContext().setAuthentication(authentication);

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
                System.out.println(email);
        if (email == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Email not found in OAuth2 response.");
            return;
        }

        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;

        System.out.println(userOptional);

        if (userOptional.isEmpty()) {
            GoogleUserDTO googleUserDTO = new GoogleUserDTO();
            googleUserDTO.setEmail(email);
            googleUserDTO.setFirstName(oAuth2User.getAttribute("given_name"));
            googleUserDTO.setLastName(oAuth2User.getAttribute("family_name"));

            System.out.println(googleUserDTO);
            user = userService.registerGoogleUser(googleUserDTO);
            System.out.println(user);
        } else {
            user = userOptional.get();
            System.out.println(user);
        }

        // If not approved, redirect to frontend page that shows info
        if (!"APPROVED".equalsIgnoreCase(user.getStatus())) {
            response.sendRedirect("http://localhost:5173");
            return;
        }

        String accessToken = jwtUtil.generateAccessToken(user);
        String refreshToken = jwtUtil.generateRefreshToken(user);

        System.out.println(accessToken + "acces token, " + refreshToken + "refresh token");

        response.addHeader("Set-Cookie", CookieUtil.createAccessTokenCookie(accessToken).toString());
        response.addHeader("Set-Cookie", CookieUtil.createRefreshTokenCookie(refreshToken).toString());

        System.out.println("cookies are set");
        // 👇 Redirect to frontend app (e.g., dashboard)
        response.sendRedirect("http://localhost:5173");
        System.out.println("redirecting");
    }
}
