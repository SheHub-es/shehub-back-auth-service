package es.shehub.auth_service.services;

import java.time.Duration;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

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

    public UserCreatedDTO login(LoginRequestDTO request, HttpServletResponse response) {
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(request.getEmail());

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userDetails.getUsername(), request.getPassword()));

            User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new ShehubException("Invalid credentials", HttpStatus.UNAUTHORIZED));

            String accessToken = jwtUtil.generateAccessToken(user);
            String refreshToken = jwtUtil.generateRefreshToken(user);

            ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .secure(true) 
                .path("/")
                .maxAge(Duration.ofMinutes(120))
                .sameSite("Strict") 
                .build();

            ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", refreshToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/api/auth/refresh-token")
                    .maxAge(Duration.ofDays(7))
                    .sameSite("None")
                    .build();

            response.setHeader("Set-Cookie", accessTokenCookie.toString());
            response.addHeader("Set-Cookie", refreshTokenCookie.toString());

            return userMapper.toUserCreatedDTO(user);
        } catch (Exception e) {
                throw new ShehubException("Invalid credentials", HttpStatus.UNAUTHORIZED);
        }
    }

    public void logout(HttpServletResponse response) {
        // Create expired cookies to clear them on client side
        ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", "")
            .httpOnly(true)
            .secure(true)
            .path("/")
            .maxAge(0)  // Expire immediately
            .sameSite("Strict")
            .build();

        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", "")
            .httpOnly(true)
            .secure(true)
            .path("/api/auth/refresh-token")
            .maxAge(0)  // Expire immediately
            .sameSite("None") 
            .build();

        response.setHeader("Set-Cookie", accessTokenCookie.toString());
        response.addHeader("Set-Cookie", refreshTokenCookie.toString());
    }
}
