package es.shehub.auth_service.services;

import org.springframework.stereotype.Service;

import es.shehub.auth_service.repositories.RoleRepository;
import es.shehub.auth_service.repositories.UserRepository;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
}
