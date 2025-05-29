package es.shehub.auth_service.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import es.shehub.auth_service.config.ApiPaths;
import es.shehub.auth_service.exceptions.ShehubException;
import es.shehub.auth_service.models.dtos.LoginRequestDTO;
import es.shehub.auth_service.models.dtos.UserCreatedDTO;
import es.shehub.auth_service.services.AuthService;
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

    /**
     * Authenticates a user based on provided credentials.
     * 
     * Sets secure HttpOnly cookies with access and refresh tokens if successful.
     * Returns basic user data needed by the frontend.
     * 
     * @param request contains the user email and password
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
     * @param response the HTTP response to which the access token cookie will be added
     * @return HTTP 200 with success message if token was refreshed,
     *         or HTTP 401 with a Spanish error message in case of failure
     */
    @PostMapping(ApiPaths.REFRESH_TOKEN_COOKIE_PATH)
    public ResponseEntity<String> refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
        authService.refreshToken(request, response);
        return ResponseEntity.ok("Access token actualizado correctamente.");
    }


}
