package es.shehub.auth_service.seeders;

import java.util.List;

import org.springframework.stereotype.Component;

import es.shehub.auth_service.models.entities.Role;
import es.shehub.auth_service.repositories.RoleRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class RoleSeeder {
    private final RoleRepository roleRepository;

    @PostConstruct
    public void seedRoles() {
        List<String> roles = List.of("USER", "MENTOR", "ADMIN");

        for (String roleName : roles) {
            roleRepository.findByNameIgnoreCase(roleName).orElseGet(() -> {
                Role role = new Role();
                role.setName(roleName);
                return roleRepository.save(role);
            });
        }

        System.out.println("✅ Roles seeded.");
    }
}
