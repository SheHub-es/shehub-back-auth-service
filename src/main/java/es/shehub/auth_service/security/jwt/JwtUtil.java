package es.shehub.auth_service.security.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import es.shehub.auth_service.models.entities.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.NoArgsConstructor;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import java.util.List;

/**
 * Utility class for handling JWT token operations such as creation, parsing, and validation.
 * 
 * Generates access and refresh tokens with embedded user information and expiration settings.
 * Also provides methods to extract information from tokens and check token validity.
 * 
 * The secret key for signing tokens is injected from .env via {@code JWT_SECRET_KEY}.
 * 
 * This component is stateless and safe to be used as a singleton.
 */
@NoArgsConstructor
@Component
public class JwtUtil {
    
    @Value("${JWT_SECRET_KEY}")
    private String SECRET_KEY;

    /**
     * Generates a JWT access token for a given user.
     * 
     * @param user the authenticated user
     * @return a signed JWT token valid for 2 hours, containing the user's email and role
     */
    public String generateAccessToken(User user) {
        String roleName = "ROLE_" + user.getRole().getName().toUpperCase(); 
        return Jwts.builder()
        .setSubject(user.getEmail())
        .claim("authorities", List.of(roleName))
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 )) // 1 hour
        .signWith(getSigninKey(), SignatureAlgorithm.HS256)
        .compact();
    }

    /**
     * Generates a JWT refresh token for a given user.
     * 
     * @param user the authenticated user
     * @return a signed JWT token valid for 7 days, containing the user's email
     */
    public String generateRefreshToken(User user) {
        return Jwts.builder()
            .setSubject(user.getEmail())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7)) // 7 days
            .signWith(getSigninKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    /**
     * Extracts the email (subject) from a given JWT token.
     * 
     * @param token the JWT token
     * @return the email (subject) embedded in the token
     */
    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * Validates a token by checking that it matches the expected email and is not expired.
     * 
     * @param token the JWT token to validate
     * @param expectedEmail the email expected to be found in the token
     * @return {@code true} if the token is valid and not expired; {@code false} otherwise
     */
    public boolean validateToken(String token, String expectedEmail) {
    final String username = extractUsername(token);
    return username.equals(expectedEmail) && !isTokenExpired(token);
    }

    /**
     * Checks whether the JWT token is expired.
     * 
     * @param token the JWT token
     * @return {@code true} if the token is expired; {@code false} otherwise
     */
    private boolean isTokenExpired(String token) {
        final Date expiration = Jwts.parserBuilder()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return expiration.before(new Date());
    }

    /**
     * Retrieves the secret signing key used to sign and parse tokens.
     * 
     * @return a {@link Key} instance derived from the configured secret
     */
    private Key getSigninKey() {
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}