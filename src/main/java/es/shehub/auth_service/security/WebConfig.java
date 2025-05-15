package es.shehub.auth_service.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import es.shehub.auth_service.config.ApiPaths;
import io.micrometer.common.lang.NonNull;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(@NonNull CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(ApiPaths.FRONTEND_URL)
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}
