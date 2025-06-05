package es.shehub.auth_service.services;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;

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
import es.shehub.auth_service.utils.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
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
     * - Returns the registered user data to continue the registration/login process
     * on the frontend.
     * - Sets access and refresh token cookies in the response.
     * 
     * If the email is not registered or the credentials are invalid, a
     * {@link ShehubException}
     * is thrown with message "Invalid credentials" and HTTP status 401
     * (UNAUTHORIZED).
     *
     * @param request  the login request containing email and password
     * @param response the {@link HttpServletResponse} where cookies will be set
     * @return the {@link UserCreatedDTO} containing user data
     * @throws ShehubException if authentication fails
     */

    public UserCreatedDTO login(LoginRequestDTO request, HttpServletResponse response) {
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(request.getEmail());

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userDetails.getUsername(), request.getPassword()));

            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new ShehubException("Credenciales inválidas", HttpStatus.UNAUTHORIZED));

            String accessToken = jwtUtil.generateAccessToken(user);
            String refreshToken = jwtUtil.generateRefreshToken(user);

            response.addHeader("Set-Cookie", CookieUtil.createAccessTokenCookie(accessToken).toString());
            response.addHeader("Set-Cookie", CookieUtil.createRefreshTokenCookie(refreshToken).toString());

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
     * - The refresh token cookie (scoped to /api/auth/refresh-token) is also
     * invalidated.
     *
     * This method does not require authentication logic beyond cookie expiration.
     *
     * @param response the {@link HttpServletResponse} where expired cookies will be
     *                 set
     */

    public void logout(HttpServletResponse response) {
        

        response.addHeader("Set-Cookie", CookieUtil.createExpiredAccessTokenCookie(null).toString());
        response.addHeader("Set-Cookie", CookieUtil.createExpiredRefreshTokenCookie(null).toString());
    }

    /**
     * Refreshes the access token using the refresh token sent in the HTTP cookies.
     * This method extracts the refresh token from the request cookies, validates
     * it, and if valid, generates a new access token and sends it back as a secure
     * HTTP-only cookie.
     *
     * Throws a {@link ShehubException} with HTTP 401 status if the refresh token is
     * missing, invalid, expired, or if the user does not exist.
     *
     * @param request  the incoming {@link HttpServletRequest} containing the
     *                 cookies
     * @param response the {@link HttpServletResponse} where the new access token
     *                 cookie will be set
     * @throws ShehubException if the refresh token is missing, invalid, expired, or
     *                         user not found
     */
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            throw new ShehubException("Token de actualización no encontrado", HttpStatus.UNAUTHORIZED);
        }

        Optional<Cookie> refreshTokenCookie = Arrays.stream(cookies)
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .findFirst();

        if (refreshTokenCookie.isEmpty()) {
            throw new ShehubException("Token de actualización no encontrado", HttpStatus.UNAUTHORIZED);
        }

        String refreshToken = refreshTokenCookie.get().getValue();

        String userEmail;
        try {
            userEmail = jwtUtil.extractUsername(refreshToken);
        } catch (Exception e) {
            throw new ShehubException("Token de actualización inválido", HttpStatus.UNAUTHORIZED);
        }

        if (!jwtUtil.validateToken(refreshToken, userEmail)) {
            throw new ShehubException("Token de actualización expirado o inválido", HttpStatus.UNAUTHORIZED);
        }

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ShehubException("Usuario no encontrado", HttpStatus.UNAUTHORIZED));

        String newAccessToken = jwtUtil.generateAccessToken(user);

        response.setHeader("Set-Cookie", CookieUtil.createAccessTokenCookie(newAccessToken).toString());
    }
}
