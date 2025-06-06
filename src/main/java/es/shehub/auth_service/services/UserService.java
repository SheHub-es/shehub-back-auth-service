package es.shehub.auth_service.services;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import es.shehub.auth_service.exceptions.ShehubException;
import es.shehub.auth_service.mappers.UserMapper;
import es.shehub.auth_service.models.dtos.GoogleUserDTO;
import es.shehub.auth_service.models.dtos.UpdateRoleRequestDTO;
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

            Role role = roleRepository.findByNameIgnoreCase(roleName)
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

        Role role = findRoleByName(dto.getRole());
        newUser.setRole(role);
        return userRepository.save(newUser);
    }

    /**
     * Updates the status of a user identified by the given ID.
     * Validates that the new status is one of the allowed values: APPROVED,
     * PENDING, or REJECTED.
     * Saves the updated user and returns its corresponding UserDTO.
     *
     * @param request the request object containing the new status
     * @param id      the string representation of the user ID (UUID)
     * @return the updated UserDTO
     * @throws ShehubException if the user is not found, the UUID is invalid, or the
     *                         status is not valid
     */
    public UserDTO updateUserStatus(UpdateStatusRequestDTO request, String id) {

        User user = findUserById(id);

        String newStatus = request.getStatus().toUpperCase();

        if (!List.of("APPROVED", "PENDING", "REJECTED").contains(newStatus)) {
            throw new ShehubException("Selected status not valid.", HttpStatus.BAD_REQUEST);
        }
        user.setStatus(newStatus);
        userRepository.save(user);

        return userMapper.toUserDTO(user);

    }

    /**
     * Updates the role of an existing user identified by the given ID.
     * 
     * Finds the user by ID and the role by name, then sets the new role to the
     * user,
     * saves the updated user in the repository, and returns the updated user as a
     * DTO.
     * 
     * @param request the DTO containing the new role name to assign to the user
     * @param id      the string representation of the user's UUID
     * @return the updated UserDTO reflecting the new role assignment
     * @throws ShehubException if the user ID is invalid, the user is not found, or
     *                         the role name does not exist
     */
    public UserDTO updateUserRole(UpdateRoleRequestDTO request, String id) {

        if (request.getRoleName() == null || request.getRoleName().isBlank()) {
            throw new ShehubException("Role name must be provided", HttpStatus.BAD_REQUEST);
        }
        User user = findUserById(id);
        Role role = findRoleByName(request.getRoleName());

        user.setRole(role);
        User updatedUser = userRepository.save(user);

        return userMapper.toUserDTO(updatedUser);
    }

    /**
     * Deletes a user by their ID after verifying authorization.
     * A user can delete their own account, and admins can delete any account.
     *
     * @param userId         the ID of the user to delete
     * @param authentication the current authenticated user's security context
     * @throws ShehubException if the authenticated user is not authorized,
     *                         if the user is not found, or if a deletion error
     *                         occurs
     */
    public void deleteUserById(String userId, Authentication authentication) {
        String authenticatedUsername = authentication.getName();
        User authenticatedUser = userRepository.findByEmail(authenticatedUsername)
                .orElseThrow(() -> new ShehubException("Authenticated user not found", HttpStatus.UNAUTHORIZED));

        boolean isAdmin = authenticatedUser.getRole().getName().equalsIgnoreCase("ADMIN");
        boolean isSelf = authenticatedUser.getId().toString().equals(userId);

        if (!isAdmin && !isSelf) {
            throw new ShehubException("You are not authorized to delete this user", HttpStatus.FORBIDDEN);
        }

        User userToDelete = findUserById(userId);
        try {
            userRepository.delete(userToDelete);
        } catch (Exception e) {
            throw new ShehubException("Something went wrong when deleting a user", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    // HELPER METHODS

    /**
     * Finds a User entity by its string ID.
     * Parses the string to a UUID and fetches the user from the repository.
     *
     * @param id the string representation of the user ID (UUID)
     * @return the User entity
     * @throws ShehubException if the UUID format is invalid or the user with the
     *                         given ID does not exist
     */
    public User findUserById(String id) {
        try {
            UUID userId = UUID.fromString(id);
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new ShehubException("User with such ID not found", HttpStatus.NOT_FOUND));
            return user;
        } catch (IllegalArgumentException e) {
            throw new ShehubException("Invalid UUID format", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Finds a Role entity by its name.
     *
     * @param roleName the name of the role to find
     * @return the Role entity matching the given name
     * @throws ShehubException if the role is not found in the database
     */
    public Role findRoleByName(String roleName) {
        return roleRepository.findByNameIgnoreCase(roleName)
                .orElseThrow(() -> new ShehubException("Rol no encontrado.", HttpStatus.BAD_REQUEST));
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
