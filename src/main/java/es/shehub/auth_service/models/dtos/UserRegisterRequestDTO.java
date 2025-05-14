package es.shehub.auth_service.models.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UserRegisterRequestDTO {
    private String email;
    private String password;
    private String firstName;
    private String lastName;
    private String role;
}
