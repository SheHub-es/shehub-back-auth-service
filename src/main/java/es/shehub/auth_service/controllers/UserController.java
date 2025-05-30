package es.shehub.auth_service.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;

import es.shehub.auth_service.config.ApiPaths;
import es.shehub.auth_service.models.dtos.UserCreatedDTO;
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
    public ResponseEntity<UserCreatedDTO> registerUser(@RequestBody UserRegisterRequestDTO request) {

        UserCreatedDTO newUser = userService.createUser(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(newUser);
    }

    /**
     * Creates a new admin user. Accessible only to ADMINs.
     */
    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping(ApiPaths.CREATE_ADMIN_PATH)
    public ResponseEntity<UserCreatedDTO> createAdmin(@RequestBody UserRegisterRequestDTO request) {

        UserCreatedDTO newAdmin = userService.createAdmin(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(newAdmin);
    }

}
