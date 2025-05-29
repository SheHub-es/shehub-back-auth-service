package es.shehub.auth_service.models.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO representing basic user data received from Google after authentication.
 * This is used to register the user in the system if they do not already exist.
 */

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class GoogleUserDTO {
    private String email;
    private String firstName;
    private String lastName;
    private String provider = "GOOGLE";
    private String role = "USER";
}
