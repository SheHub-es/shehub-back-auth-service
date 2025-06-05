package es.shehub.auth_service.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import es.shehub.auth_service.config.ApiPaths;
import es.shehub.auth_service.exceptions.ShehubException;
import es.shehub.auth_service.models.dtos.LoginRequestDTO;
import es.shehub.auth_service.models.dtos.PasswordResetRequestDTO;
import es.shehub.auth_service.models.dtos.UserCreatedDTO;
import es.shehub.auth_service.services.AuthService;
import es.shehub.auth_service.services.PasswordResetService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

/**
 * Controller responsible for handling authentication-related endpoints.
 */
@AllArgsConstructor
@RestController
public class AuthController {
    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    /**
     * Authenticates a user based on provided credentials.
     * 
     * Sets secure HttpOnly cookies with access and refresh tokens if successful.
     * Returns basic user data needed by the frontend.
     * 
     * @param request  contains the user email and password
     * @param response used to set authentication cookies
     * @return 200 OK with user data, or 401 Unauthorized on invalid credentials
     */
    @PostMapping(ApiPaths.LOGIN_PATH)
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDTO request, HttpServletResponse response) {
        try {
            UserCreatedDTO userCreatedDTO = authService.login(request, response);
            return ResponseEntity.ok(userCreatedDTO);
        } catch (ShehubException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }

    /**
     * Logs the user out by clearing authentication cookies.
     * 
     * @param response used to clear JWT cookies
     * @return 204 No Content on success
     */
    @PostMapping(ApiPaths.LOGOUT_PATH)
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        authService.logout(response);

        return ResponseEntity.noContent().build();
    }

    /**
     * Endpoint to refresh the access token using a valid refresh token.
     * The refresh token is expected to be in the request cookies.
     * If valid, a new access token is returned as an HTTP-only cookie.
     *
     * @param request  the HTTP request containing cookies
     * @param response the HTTP response to which the access token cookie will be
     *                 added
     * @return HTTP 200 with success message if token was refreshed,
     *         or HTTP 401 with a Spanish error message in case of failure
     */
    @PostMapping(ApiPaths.REFRESH_TOKEN_COOKIE_PATH)
    public ResponseEntity<String> refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
        authService.refreshToken(request, response);
        return ResponseEntity.ok("Access token actualizado correctamente.");
    }

    /**
     * Endpoint to request a password reset email.
     * Expects a JSON body containing an "email" key with the user's email address.
     * If the email exists in the system, a password reset link with a token will be
     * sent to that email.
     * For security, the response is always 200 OK regardless of whether the email
     * exists.
     * 
     * @param body a map containing the "email" key with the user's email address
     * @return {@code ResponseEntity} with HTTP 200 and a message indicating that
     *         the reset email was sent if the account exists
     */
    @PostMapping(ApiPaths.REQUEST_PASSWORD_RESET_PATH)
    public ResponseEntity<?> requestReset(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        passwordResetService.sendResetEmail(email);
        return ResponseEntity.ok().body("Reset email sent if account exists.");
    }

    /**
     * Endpoint to reset the user's password.
     * Expects a JSON body with a {@link PasswordResetRequestDTO} containing the
     * reset token and new password.
     * Validates the token and resets the password if valid.
     * Returns HTTP 200 on success or HTTP 401 if the token is invalid or expired.
     * 
     * @param request the password reset request DTO containing the token and new
     *                password
     * @return {@code ResponseEntity} with status 200 and success message or 401 and
     *         error message on failure
     */
    @PostMapping(ApiPaths.RESET_PASSWORD_PATH)
    public ResponseEntity<?> resetPassword(@RequestBody PasswordResetRequestDTO request) {
        try {
            passwordResetService.resetPassword(request.getToken(), request.getNewPassword());
            return ResponseEntity.ok("Password reset successful.");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token.");
        }
    }

    @GetMapping("/success")
    public ResponseEntity<String> success() {
        return ResponseEntity.ok("OAuth2 login successful!");
    }

}
