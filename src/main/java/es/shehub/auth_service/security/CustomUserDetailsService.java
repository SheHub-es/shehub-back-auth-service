package es.shehub.auth_service.security;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import org.springframework.stereotype.Service;

import es.shehub.auth_service.exceptions.ShehubException;
import es.shehub.auth_service.models.entities.User;
import es.shehub.auth_service.repositories.UserRepository;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

        

@Override
    public UserDetails loadUserByUsername(String email)  {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ShehubException("No se ha encontrado el usuario con este email: " + email));

        if (!"APPROVED".equalsIgnoreCase(user.getStatus())){
            
            throw new ShehubException("El usuario no está aprobado para iniciar sesión.", HttpStatus.FORBIDDEN);
        }

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .roles(user.getRole().getName()) 
                .build();
    }
}
