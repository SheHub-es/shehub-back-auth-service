package es.shehub.auth_service.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import es.shehub.auth_service.config.ApiPaths;
import io.micrometer.common.lang.NonNull;

/**
 * Configuration class to enable and customize CORS settings
 * for the authentication service backend.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    /**
     * Configures CORS mappings to allow requests from the frontend URL,
     * specify allowed HTTP methods, headers, and support credentials.
     * 
     * @param registry the CorsRegistry to configure CORS mappings
     */
    @Override
    public void addCorsMappings(@NonNull CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(ApiPaths.FRONTEND_URL)
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE")
                .allowedHeaders("*")
                .allowCredentials(true)
                .exposedHeaders("Set-Cookie");
    }
}
