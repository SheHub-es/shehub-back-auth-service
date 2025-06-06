package es.shehub.auth_service.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;

import es.shehub.auth_service.config.ApiPaths;
import es.shehub.auth_service.exceptions.ShehubException;
import es.shehub.auth_service.models.dtos.UpdateRoleRequestDTO;
import es.shehub.auth_service.models.dtos.UpdateStatusRequestDTO;
import es.shehub.auth_service.models.dtos.UserDTO;
import es.shehub.auth_service.models.dtos.UserRegisterRequestDTO;
import es.shehub.auth_service.services.UserService;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * Registers a new user (role USER or MENTOR).
     * 
     * @param request The user registration request.
     * @return The created user details.
     */
    @PostMapping(ApiPaths.REGISTER_PATH)
    public ResponseEntity<UserDTO> registerUser(@RequestBody UserRegisterRequestDTO request) {

        UserDTO newUser = userService.createUser(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
    }

    /**
     * Endpoint to create a new admin user.
     * 
     * Access to this endpoint is restricted to users with the ADMIN role.
     * 
     * @param request the request body containing the new admin user registration
     *                details
     * @return a ResponseEntity containing the created UserDTO and HTTP status 201
     *         (Created)
     */
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping(ApiPaths.CREATE_ADMIN_PATH)
    public ResponseEntity<UserDTO> createAdmin(@RequestBody UserRegisterRequestDTO request) {

        UserDTO newAdmin = userService.createAdmin(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(newAdmin);
    }

    /**
     * Endpoint to update the status of a user identified by their userId.
     *
     * Access to this endpoint is restricted to users with the ADMIN role.
     *
     * @param userId  the UUID string of the user whose status is to be updated
     * @param request the request body containing the new status information
     * @return a ResponseEntity containing the updated UserDTO and HTTP status 200
     *         (OK)
     * @throws ShehubException if the user or status is not found or invalid
     */
    @PreAuthorize("hasRole('ADMIN')")
    @PatchMapping(ApiPaths.UPDATE_USER_STATUS_PATH)
    public ResponseEntity<UserDTO> updateUserStatus(
            @PathVariable String userId,
            @RequestBody UpdateStatusRequestDTO request) {

        UserDTO updatedUser = userService.updateUserStatus(request, userId);

        return ResponseEntity.status(HttpStatus.OK).body(updatedUser);
    }

    /**
     * Updates the role of an existing user identified by the userId.
     * 
     * This endpoint is restricted to users with the ADMIN role.
     * 
     * @param userId  the UUID string of the user whose role is to be updated
     * @param request the DTO containing the new role name to assign to the user
     * @return a ResponseEntity containing the updated UserDTO and HTTP status 200
     *         OK
     * @throws ShehubException if the user or role is not found or invalid
     */
    @PreAuthorize("hasRole('ADMIN')")
    @PatchMapping(ApiPaths.UPDATE_USER_ROLE_PATH)
    public ResponseEntity<UserDTO> updateUserRole(
            @PathVariable String userId,
            @RequestBody UpdateRoleRequestDTO request) {

        UserDTO updatedUser = userService.updateUserRole(request, userId);

        return ResponseEntity.status(HttpStatus.OK).body(updatedUser);
    }

    /**
     * Deletes a user by their ID.
     * Only authenticated users can perform this action. A user can delete their own account,
     * while users with ADMIN role can delete any account.
     *
     * @param userId         ID of the user to be deleted
     * @param authentication the current authenticated user's security context
     * @return 204 No Content response if deletion is successful
     */
    @PreAuthorize("isAuthenticated()")
    @DeleteMapping(ApiPaths.DELETE_USER_PATH)
    public ResponseEntity<Void> deleteUser(@PathVariable String userId,
            org.springframework.security.core.Authentication authentication) {
        userService.deleteUserById(userId, authentication);
        return ResponseEntity.noContent().build();
    }
}
