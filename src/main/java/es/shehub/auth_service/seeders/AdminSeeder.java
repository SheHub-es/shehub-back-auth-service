package es.shehub.auth_service.seeders;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import es.shehub.auth_service.models.entities.Role;
import es.shehub.auth_service.models.entities.User;
import es.shehub.auth_service.repositories.RoleRepository;
import es.shehub.auth_service.repositories.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
@DependsOn("roleSeeder")
public class AdminSeeder {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${ADMIN_DEFAULT_EMAIL}")
    private String defaultAdminEmail;

    @Value("${ADMIN_DEFAULT_PASSWORD}")
    private String defaultAdminPassword;

    @Value("${ADMIN_DEFAULT_FIRSTNAME}")
    private String defaultAdminFirstName;

    @Value("${ADMIN_DEFAULT_LASTNAME}")
    private String defaultAdminLastName;

    @PostConstruct
    public void seedDefaultAdmin() {
        if (userRepository.findByEmail(defaultAdminEmail).isEmpty()) {
            Role adminRole = roleRepository.findByName("ADMIN")
                    .orElseThrow(() -> new RuntimeException("Role ADMIN not found"));

            User admin = new User();
            admin.setEmail(defaultAdminEmail);
            admin.setPassword(passwordEncoder.encode(defaultAdminPassword));
            admin.setFirstName(defaultAdminFirstName);
            admin.setLastName(defaultAdminLastName);
            admin.setRole(adminRole);
            admin.setStatus("APPROVED");
            admin.setProfileCompleted(true);

            userRepository.save(admin);

            System.out.println("✅ Default admin seeded.");
        }
    }
}
