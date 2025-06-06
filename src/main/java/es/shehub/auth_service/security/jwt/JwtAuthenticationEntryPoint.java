package es.shehub.auth_service.security.jwt;

import java.io.IOException;

import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Custom implementation of AuthenticationEntryPoint used to handle unauthorized access attempts.
 *
 * This entry point is triggered whenever an unauthenticated user tries to access a protected resource.
 * Instead of redirecting to a login page (which is typical in web applications), it sends a JSON response
 * with a 401 Unauthorized status code.
 *
 * This is typically used in stateless applications (e.g., using JWT tokens) where the client handles authentication.
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    
    /**
     * Handles unauthorized access attempts by sending a 401 Unauthorized HTTP response with a JSON body.
     *
     * @param request       the HttpServletRequest that resulted in the authentication exception
     * @param response      the HttpServletResponse to be sent to the client
     * @param authException the exception that caused the invocation
     * @throws IOException if an input or output error occurs while writing to the response
     */
    @Override
    public void commence(HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.core.AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"Unauthorized\"}");
    }
}
