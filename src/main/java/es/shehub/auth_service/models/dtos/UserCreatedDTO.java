package es.shehub.auth_service.models.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UserCreatedDTO {
    private String id;
    private String role;
    private boolean profileCompleted;
    private String firstName;
    private String lastName;
}
