package es.shehub.auth_service.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;

import es.shehub.auth_service.config.ApiPaths;
import es.shehub.auth_service.models.dtos.UserDTO;
import es.shehub.auth_service.models.dtos.UserRegisterRequestDTO;
import es.shehub.auth_service.services.UserService;
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
     * Creates a new admin user. Accessible only to ADMINs.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping(ApiPaths.CREATE_ADMIN_PATH)
    public ResponseEntity<UserDTO> createAdmin(@RequestBody UserRegisterRequestDTO request) {

        UserDTO newAdmin = userService.createAdmin(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(newAdmin);
    }

}
