package es.shehub.auth_service.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;

import es.shehub.auth_service.config.ApiPaths;
import es.shehub.auth_service.exceptions.ShehubException;
import es.shehub.auth_service.models.dtos.requests.UpdatePasswordRequest;
import es.shehub.auth_service.models.dtos.requests.UpdateRoleRequestDTO;
import es.shehub.auth_service.models.dtos.requests.UpdateStatusRequestDTO;
import es.shehub.auth_service.models.dtos.requests.UpdateUserRequestDTO;
import es.shehub.auth_service.models.dtos.requests.UserRegisterRequestDTO;
import es.shehub.auth_service.models.dtos.responses.FullUserDataDTO;
import es.shehub.auth_service.models.dtos.responses.ProfileUserDataDTO;
import es.shehub.auth_service.models.dtos.responses.UserDTO;
import es.shehub.auth_service.services.UserService;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
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
     * Handles PATCH request to update user data.
     * Accepts partial updates and returns the updated profile information.
     * 
     * @param userId        the ID of the user to update
     * @param updateRequest the data to update
     * @return ResponseEntity containing the updated profile data
     */
    @PatchMapping(ApiPaths.UPDATE_USER_DATA_PATH)
    public ResponseEntity<ProfileUserDataDTO> updateUserData(@PathVariable String userId,
            @RequestBody UpdateUserRequestDTO updateRequest) {
        ProfileUserDataDTO updatedUser = userService.updateUserData(userId, updateRequest);

        return ResponseEntity.status(HttpStatus.OK).body(updatedUser);
    }

    /**
     * Endpoint for administrators to retrieve full profile data for a specific
     * user.
     *
     * Requires the ADMIN role. Combines user account information with full profile
     * data.
     *
     * @param userId the ID of the user to retrieve
     * @return HTTP 200 OK response containing the FullUserDataDTO of the specified
     *         user
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping(ApiPaths.GET_FULL_USER_DATA_PATH)
    public ResponseEntity<FullUserDataDTO> getFullUserData(@PathVariable String userId) {
        FullUserDataDTO fullUserData = userService.getFullUserData(userId);

        return ResponseEntity.status(HttpStatus.OK).body(fullUserData);
    }

    /**
     * Endpoint for administrators to retrieve a list of users with full profile
     * data.
     *
     * Requires the ADMIN role. Delegates to the service layer to fetch and combine
     * user account and project profile information.
     *
     * @return HTTP 200 OK response containing the list of FullUserDataDTO
     */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping(ApiPaths.GET_USERS_LIST_PATH)
    public ResponseEntity<List<FullUserDataDTO>> getUsersListFullUserData() {
        List<FullUserDataDTO> fullUserDataList = userService.getAllUsersFullUserDataDTO();

        return ResponseEntity.ok(fullUserDataList);
    }

    /**
     * Retrieves the authenticated user's profile information.
     *
     * This endpoint ensures that a user can only fetch their own profile data.
     * It checks the authentication details and matches them with the requested
     * userId.
     * If the request is valid, returns the user's profile information.
     *
     * @param userId         the ID of the user requesting their own profile
     * @param authentication the current authentication object representing the
     *                       logged-in user
     * @return ResponseEntity containing the user's profile data
     * @throws ShehubException if the authenticated user is not allowed to view this
     *                         profile
     */
    @PreAuthorize("isAuthenticated()")
    @GetMapping(ApiPaths.GET_USER_PROFILE_PATH)
    public ResponseEntity<ProfileUserDataDTO> getUserProfile(@PathVariable String userId,
            org.springframework.security.core.Authentication authentication) {

        ProfileUserDataDTO userProfileData = userService.getUserProfile(userId, authentication);

        return ResponseEntity.ok(userProfileData);
    }

    /**
     * Endpoint to update the password of the currently authenticated user.
     *
     * This method accepts a password update request containing the current and new passwords.
     * It delegates the password change logic to the service layer, which validates the current password  and updates it securely.
     *
     * Only authenticated users can access this endpoint.
     *
     * @param request        the request body containing the current and new
     *                       passwords
     * @param authentication the authentication object representing the currently
     *                       logged-in user
     * @return a 200 OK response with a success message if the password was changed
     *         successfully
     */
    @PreAuthorize("isAuthenticated()")
    @PostMapping(ApiPaths.UPDATE_USER_PASSWORD_PATH)
    public ResponseEntity<String> updateUserPassword(@RequestBody UpdatePasswordRequest request,
            org.springframework.security.core.Authentication authentication) {

        userService.changePassword(request, authentication);

        return ResponseEntity.ok("Password updated successfully");
    }

    /**
     * Deletes a user by their ID.
     * Only authenticated users can perform this action. A user can delete their own
     * account,
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
