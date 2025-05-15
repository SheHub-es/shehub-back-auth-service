package es.shehub.auth_service.services;

import java.time.Duration;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import es.shehub.auth_service.config.ApiPaths;
import es.shehub.auth_service.exceptions.ShehubException;
import es.shehub.auth_service.mappers.UserMapper;
import es.shehub.auth_service.models.dtos.LoginRequestDTO;
import es.shehub.auth_service.models.dtos.UserCreatedDTO;
import es.shehub.auth_service.models.entities.User;
import es.shehub.auth_service.repositories.UserRepository;
import es.shehub.auth_service.security.CustomUserDetailsService;
import es.shehub.auth_service.security.jwt.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@Service
public class AuthService {
    private final CustomUserDetailsService customUserDetailsService;
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;


    /**
     * Authenticates a user by verifying the email-password pair for LOCAL users.
     * 
     * If authentication succeeds:
     * - Returns the registered user data to continue the registration/login process on the frontend.
     * - Sets access and refresh token cookies in the response.
     * 
     * If the email is not registered or the credentials are invalid, a {@link ShehubException} 
     * is thrown with message "Invalid credentials" and HTTP status 401 (UNAUTHORIZED).
     *
     * @param request  the login request containing email and password
     * @param response the {@link HttpServletResponse} where cookies will be set
     * @return the {@link UserCreatedDTO} containing user data
     * @throws ShehubException if authentication fails
     */

    public UserCreatedDTO login(LoginRequestDTO request, HttpServletResponse response) {
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(request.getEmail());

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userDetails.getUsername(), request.getPassword()));

            User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new ShehubException("Credenciales inválidas", HttpStatus.UNAUTHORIZED));

            String accessToken = jwtUtil.generateAccessToken(user);
            String refreshToken = jwtUtil.generateRefreshToken(user);

            ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .secure(true) 
                .path(ApiPaths.ACCESS_TOKEN_COOKIE_PATH)
                .maxAge(Duration.ofMinutes(120))
                .sameSite("Strict") 
                .build();

            ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", refreshToken)
                    .httpOnly(true)
                    .secure(true)
                    .path(ApiPaths.REFRESH_TOKEN_COOKIE_PATH)
                    .maxAge(Duration.ofDays(7))
                    .sameSite("None")
                    .build();

            response.setHeader("Set-Cookie", accessTokenCookie.toString());
            response.addHeader("Set-Cookie", refreshTokenCookie.toString());

            return userMapper.toUserCreatedDTO(user);
        } catch (Exception e) {
                throw new ShehubException("Credenciales inválidas", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Logs out the user by clearing authentication cookies.
     * 
     * This method sets expired versions of the access and refresh token cookies,
     * instructing the client to remove them.
     *
     * - The access token cookie is invalidated by setting its max age to 0.
     * - The refresh token cookie (scoped to /api/auth/refresh-token) is also invalidated.
     *
     * This method does not require authentication logic beyond cookie expiration.
     *
     * @param response the {@link HttpServletResponse} where expired cookies will be set
     */

    public void logout(HttpServletResponse response) {
        // Create expired cookies to clear them on client side
        ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", "")
            .httpOnly(true)
            .secure(true)
            .path(ApiPaths.ACCESS_TOKEN_COOKIE_PATH)
            .maxAge(0)  // Expire immediately
            .sameSite("Strict")
            .build();

        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", "")
            .httpOnly(true)
            .secure(true)
            .path(ApiPaths.REFRESH_TOKEN_COOKIE_PATH)
            .maxAge(0)  // Expire immediately
            .sameSite("None") 
            .build();

        response.setHeader("Set-Cookie", accessTokenCookie.toString());
        response.addHeader("Set-Cookie", refreshTokenCookie.toString());
    }
}
