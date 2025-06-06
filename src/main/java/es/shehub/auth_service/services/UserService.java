package es.shehub.auth_service.services;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import es.shehub.auth_service.exceptions.ShehubException;
import es.shehub.auth_service.mappers.UserMapper;
import es.shehub.auth_service.models.dtos.GoogleUserDTO;
import es.shehub.auth_service.models.dtos.UpdateStatusRequestDTO;
import es.shehub.auth_service.models.dtos.UserDTO;
import es.shehub.auth_service.models.dtos.UserRegisterRequestDTO;
import es.shehub.auth_service.models.entities.Role;
import es.shehub.auth_service.models.entities.User;
import es.shehub.auth_service.repositories.RoleRepository;
import es.shehub.auth_service.repositories.UserRepository;
import lombok.AllArgsConstructor;

/**
 * Handles user registration logic for different types of users (standard,
 * admin, Google).
 */
@AllArgsConstructor
@Service
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;

    /**
     * Handles user creation for any role by performing common steps:
     * mapping DTO to entity, validating role, encoding password, and saving.
     *
     * @param request  the data required to create the user
     * @param roleName the role to assign to the user
     * @return the DTO representing the created user
     * @throws ShehubException if the role is invalid, user creation fails, or
     *                         persistence errors occur
     */
    public UserDTO createUserInternal(UserRegisterRequestDTO request, String roleName) {

        try {
            if (!isEmailAvailable(request.getEmail())) {
                throw new ShehubException("El usuario con este email ya existe.", HttpStatus.CONFLICT);
            }

            User user = userMapper.toUser(request);

            if ("ADMIN".equalsIgnoreCase(roleName)) {
                user.setStatus("APPROVED");
            } else {
                if (!List.of("USER", "MENTOR").contains(request.getRole().toUpperCase())) {
                    throw new ShehubException("Rol seleccionado no válido.", HttpStatus.BAD_REQUEST);
                }
            }

            Role role = roleRepository.findByName(roleName)
                    .orElseThrow(() -> new ShehubException("Rol no encontrado.", HttpStatus.BAD_REQUEST));
            user.setRole(role);
            if (request.getPassword() != null) {
                user.setPassword(passwordEncoder.encode(request.getPassword()));
            }
            User savedUser = userRepository.save(user);
            return userMapper.toUserDTO(savedUser);
        } catch (Exception e) {

            System.err.println("Error creating user: " + e.getClass().getName() + " - " + e.getMessage());
            e.printStackTrace();
            throw new ShehubException("El registro de usuario ha fallado. Por favor, inténtalo más tarde",
                    HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    /**
     * Registers a regular user (USER or MENTOR) with validation of email and
     * password.
     *
     * @param request the registration request containing user details
     * @return the created user DTO
     * @throws ShehubException if the email is in use or password is invalid
     */

    public UserDTO createUser(UserRegisterRequestDTO request) {

        if (!isPasswordFormatValid(request.getPassword())) {
            throw new ShehubException("La contraseña debe tener cómo mínimo 8 caracteres", HttpStatus.BAD_REQUEST);
        }

        return createUserInternal(request, request.getRole());
    }

    /**
     * Creates a user with the ADMIN role.
     * This should only be called by an authorized admin.
     *
     * @param request the registration request containing admin details
     * @return the created admin user DTO
     */
    public UserDTO createAdmin(UserRegisterRequestDTO request) {
        return createUserInternal(request, "ADMIN");
    }

    /**
     * Registers a new user in the system based on Google OAuth2 user data.
     * 
     * This method performs the following steps:
     * 
     * Checks if the email provided in the GoogleUserDTO is already registered.
     * If the email is available, maps the Google user data to a new User entity.
     * Fetches the role specified in the DTO and assigns it to the new user.
     * Saves the new user in the database and returns the saved entity.
     *
     * @param dto the GoogleUserDTO containing user information from Google OAuth2
     * @return the newly created User entity saved in the repository
     * @throws ShehubException if the email is already registered or the specified
     *                         role is not found
     */
    public User registerGoogleUser(GoogleUserDTO dto) {

        if (!isEmailAvailable(dto.getEmail())) {
            throw new ShehubException("User already exists", HttpStatus.BAD_REQUEST);
        }

        User newUser = userMapper.fromGoogleUser(dto);

        Role role = roleRepository.findByName(dto.getRole())
                .orElseThrow(() -> new ShehubException("Rol no encontrado.", HttpStatus.BAD_REQUEST));
        newUser.setRole(role);
        return userRepository.save(newUser);
    }

    public UserDTO updateUserStatus(UpdateStatusRequestDTO request, String id) {

        try {
            UUID userId = UUID.fromString(id);
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new ShehubException("User with such ID not found", HttpStatus.NOT_FOUND));

            String newStatus = request.getStatus().toUpperCase();

            if (!List.of("APPROVED", "PENDING", "REJECTED").contains(newStatus)) {
                    throw new ShehubException("Selected status not valid.", HttpStatus.BAD_REQUEST);
                }
            user.setStatus(newStatus);
            userRepository.save(user);

            return userMapper.toUserDTO(user);
        } catch (IllegalArgumentException e) {
            throw new ShehubException("Invalid UUID format", HttpStatus.BAD_REQUEST);
        }

    }

    // VALIDATIONS
    /**
     * Validates whether the provided email is available (i.e., not already used) in
     * the database.
     *
     * @param email the email to check
     * @return {@code true} if the email is available, {@code false} otherwise
     */

    private boolean isEmailAvailable(String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        return userOpt.isEmpty();
    }

    /**
     * Validates whether the provided password meets basic format requirements.
     *
     * Currently, this method only checks for a minimum password length of 8
     * characters.
     * Additional constraints (e.g., uppercase letters, digits, symbols) can be
     * added later as needed.
     *
     * @param password the password to validate
     * @return {@code true} if the password is valid, {@code false} otherwise
     */
    public static boolean isPasswordFormatValid(String password) {
        if (password == null) {
            return false;
        }

        // Basic requirement: minimum length of 8 characters
        return password.length() >= 8;
    }
}
