package es.shehub.auth_service.models.dtos.requests;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class AuthUserUpdateRequestDTO {
    private String firstName;
    private String lastName;
}
