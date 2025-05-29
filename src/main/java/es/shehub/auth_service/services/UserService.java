package es.shehub.auth_service.services;

import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import es.shehub.auth_service.exceptions.ShehubException;
import es.shehub.auth_service.mappers.UserMapper;
import es.shehub.auth_service.models.dtos.GoogleUserDTO;
import es.shehub.auth_service.models.dtos.UserCreatedDTO;
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
     * @throws ShehubException if the role is invalid, user creation fails, or persistence errors occur
     */
    public UserCreatedDTO createUserInternal(UserRegisterRequestDTO request, String roleName) {

        try {
            User user = userMapper.toUser(request);

            if (!List.of("USER", "MENTOR").contains(request.getRole().toUpperCase())) {
                throw new ShehubException("Invalid role selected.", HttpStatus.BAD_REQUEST);
            }
            Role role = roleRepository.findByName(roleName)
                    .orElseThrow(() -> new ShehubException("Role not found", HttpStatus.BAD_REQUEST));
            user.setRole(role);
            if (request.getPassword() != null) {
                user.setPassword(passwordEncoder.encode(request.getPassword()));
            }
            User savedUser = userRepository.save(user);
            return userMapper.toUserCreatedDTO(savedUser);
        } catch (Exception e) {
            throw new ShehubException("User registration failed. Please try again later.",
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

    public UserCreatedDTO createUser(UserRegisterRequestDTO request) {
        if (!isEmailAvailable(request.getEmail())) {
            throw new ShehubException("The email address is already in use.", HttpStatus.BAD_REQUEST);
        }

        if (!isPasswordFormatValid(request.getPassword())) {
            throw new ShehubException("The password should contain at least 8 characters", HttpStatus.BAD_REQUEST);
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
    public UserCreatedDTO createAdmin(UserRegisterRequestDTO request) {
        return createUserInternal(request, "ADMIN");
    }

    /**
     * Registers a new user authenticated through Google.
     * Assumes password is not required.
     *
     * @param googleUserDto the user data received from Google authentication
     * @return the created user DTO
     * @throws ShehubException if the email is already registered or registration fails
     */
    public UserCreatedDTO registerGoogleUser(GoogleUserDTO googleUserDto) {
        if (!isEmailAvailable(googleUserDto.getEmail())) {
            throw new ShehubException("User already registered.", HttpStatus.BAD_REQUEST);
        }

        UserRegisterRequestDTO request = userMapper.fromGoogleUser(googleUserDto);

        return createUserInternal(request, request.getRole());
    }

    /**
     * Validates whether the provided email is available (i.e., not already used) in the database.
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
     * Additional constraints (e.g., uppercase letters, digits, symbols) can be added later as needed.
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
