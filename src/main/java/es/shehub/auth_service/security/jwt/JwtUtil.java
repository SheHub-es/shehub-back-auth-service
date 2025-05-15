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

@NoArgsConstructor
@Component
public class JwtUtil {
    
    @Value("${JWT_SECRET_KEY}")
    private String SECRET_KEY;


    public String generateToken(User user) {
        String roleName = "ROLE_" + user.getRole().getName().toUpperCase(); 
        return Jwts.builder()
        .setSubject(user.getEmail())
        .claim("authorities", List.of(roleName))
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2)) // 2 hours
        .signWith(getSigninKey(), SignatureAlgorithm.HS256)
        .compact();
}

    public String generateRefreshToken(User user) {
        return Jwts.builder()
            .setSubject(user.getEmail())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7)) // 7 days
            .signWith(getSigninKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateToken(String token, String expectedEmail) {
    final String username = extractUsername(token);
    return username.equals(expectedEmail) && !isTokenExpired(token);
}

    private boolean isTokenExpired(String token) {
        final Date expiration = Jwts.parserBuilder()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return expiration.before(new Date());
    }

    private Key getSigninKey() {
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}