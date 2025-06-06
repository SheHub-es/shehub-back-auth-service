package es.shehub.auth_service.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import es.shehub.auth_service.config.ApiPaths;
import es.shehub.auth_service.security.jwt.JwtAuthenticationEntryPoint;
import es.shehub.auth_service.security.jwt.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

        /**
         * Configures the security filter chain with JWT authentication, stateless
         * session, and route access rules.
         */
        @Bean
        public SecurityFilterChain securityFilterChain(
                        HttpSecurity http,
                        JwtAuthenticationFilter jwtAuthenticationFilter,
                        AuthenticationProvider authenticationProvider,
                        OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler,
                        JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint) throws Exception {
                http
                                // Allow CORS with default config
                                .cors(Customizer.withDefaults())
                                // Disable CSRF for stateless JWT-based authentication
                                .csrf(csrf -> csrf.disable())
                                .authorizeHttpRequests(authorize -> authorize
                                                // Public auth endpoints (login, register, etc)
                                                .requestMatchers(ApiPaths.BASE_API + "/auth/**").permitAll()
                                                // Admin endpoints
                                                .requestMatchers(ApiPaths.BASE_API + "/admin/**").hasRole("ADMIN")
                                                // All other endpoints require authentication
                                                .anyRequest().authenticated())
                                // Use stateless session (no server-side session)
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                // Register custom auth provider and JWT filter
                                .authenticationProvider(authenticationProvider)
                                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                                .oauth2Login(oauth2 -> oauth2
                                                .authorizationEndpoint(authz -> authz
                                                                // default base URI for OAuth2 authorization requests
                                                                .baseUri("/oauth2/authorization"))
                                                .redirectionEndpoint(redir -> redir
                                                                // your custom callback URL for OAuth2 login
                                                                .baseUri(ApiPaths.BASE_API + "/auth/oauth2/callback/*"))
                                                .successHandler(oAuth2AuthenticationSuccessHandler))
                                // Disable default form login page (you have a frontend login form)
                                .formLogin(form -> form.disable())
                                .exceptionHandling(ex -> ex
                                                .authenticationEntryPoint(jwtAuthenticationEntryPoint));
                return http.build();
        }

        /**
         * Provides password encoder used for encoding and matching user passwords.
         */
        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        /**
         * Configures the authentication provider with custom user details service and
         * password encoder.
         */
        @Bean
        public AuthenticationProvider authenticationProvider(PasswordEncoder passwordEncoder,
                        CustomUserDetailsService customUserDetailsService) {
                DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
                authProvider.setUserDetailsService(customUserDetailsService);
                authProvider.setPasswordEncoder(passwordEncoder);
                return authProvider;
        }

        /**
         * Exposes AuthenticationManager bean for use in services.
         */
        @Bean
        public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
                        throws Exception {
                return authenticationConfiguration.getAuthenticationManager();
        }
}
