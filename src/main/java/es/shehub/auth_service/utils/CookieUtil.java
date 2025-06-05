package es.shehub.auth_service.utils;

import java.time.Duration;

import org.springframework.http.ResponseCookie;

import es.shehub.auth_service.config.ApiPaths;

/**
 * Utility class for creating HTTP cookies related to authentication tokens.
 * 
 * Provides methods to create access token and refresh token cookies with
 * appropriate security settings such as HttpOnly, Secure, SameSite policies,
 * expiration durations, and cookie paths.
 * 
 * Also provides methods to create expired cookies for clearing tokens on the client side.
 */
public class CookieUtil {

    /**
     * Creates a secure, HttpOnly cookie for the access token.
     * The cookie has a max age of 60 minutes and SameSite policy set to Strict.
     *
     * @param token the JWT access token value to be set in the cookie
     * @return a {@link ResponseCookie} configured for the access token
     */
    public static ResponseCookie createAccessTokenCookie(String token) {
        return ResponseCookie.from("access_token", token)
                .httpOnly(true)
                .secure(true)
                .path(ApiPaths.ACCESS_TOKEN_COOKIE_PATH)
                .maxAge(Duration.ofMinutes(60))
                .sameSite("Strict")
                .build();
    }

    /**
     * Creates a secure, HttpOnly cookie for the refresh token.
     * The cookie has a max age of 7 days and SameSite policy set to None.
     *
     * @param token the JWT refresh token value to be set in the cookie
     * @return a {@link ResponseCookie} configured for the refresh token
     */
    public static ResponseCookie createRefreshTokenCookie(String token) {
        return ResponseCookie.from("refresh_token", token)
                .httpOnly(true)
                .secure(true)
                .path(ApiPaths.REFRESH_TOKEN_COOKIE_PATH)
                .maxAge(Duration.ofDays(7))
                .sameSite("None")
                .build();
    }

    /**
     * Creates an expired cookie for the access token.
     * This is used to clear the access token cookie on the client by setting its max age to 0.
     *
     * @param token unused parameter (can be removed, only for API consistency)
     * @return a {@link ResponseCookie} configured to expire immediately
     */
    public static ResponseCookie createExpiredAccessTokenCookie(String token) {
        return ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(true)
                .path(ApiPaths.ACCESS_TOKEN_COOKIE_PATH)
                .maxAge(0)
                .sameSite("Strict")
                .build();
    }

    /**
     * Creates an expired cookie for the refresh token.
     * This is used to clear the refresh token cookie on the client by setting its max age to 0.
     *
     * @param token unused parameter (can be removed, only for API consistency)
     * @return a {@link ResponseCookie} configured to expire immediately
     */
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
