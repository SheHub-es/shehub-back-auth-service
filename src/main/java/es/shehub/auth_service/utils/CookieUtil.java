package es.shehub.auth_service.utils;

import java.time.Duration;

import org.springframework.http.ResponseCookie;

import es.shehub.auth_service.config.ApiPaths;

public class CookieUtil {
    public static ResponseCookie createAccessTokenCookie(String token) {
        return ResponseCookie.from("access_token", token)
                .httpOnly(true)
                .secure(true)
                .path(ApiPaths.ACCESS_TOKEN_COOKIE_PATH)
                .maxAge(Duration.ofMinutes(60))
                .sameSite("Strict")
                .build();
    }

    public static ResponseCookie createRefreshTokenCookie(String token) {
        return ResponseCookie.from("refresh_token", token)
                .httpOnly(true)
                .secure(true)
                .path(ApiPaths.REFRESH_TOKEN_COOKIE_PATH)
                .maxAge(Duration.ofDays(7))
                .sameSite("None")
                .build();
    }

    // Create expired cookies to clear them on client side
    public static ResponseCookie createExpiredAccessTokenCookie(String token) {
        return ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(true)
                .path(ApiPaths.ACCESS_TOKEN_COOKIE_PATH)
                .maxAge(0)
                .sameSite("Strict")
                .build();
    }

    public static ResponseCookie createExpiredRefreshTokenCookie(String token) {
        return ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(true)
                .path(ApiPaths.REFRESH_TOKEN_COOKIE_PATH)
                .maxAge(0)
                .sameSite("None")
                .build();
    }
}
