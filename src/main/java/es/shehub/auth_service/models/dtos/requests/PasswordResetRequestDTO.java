package es.shehub.auth_service.models.dtos.requests;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class PasswordResetRequestDTO {
    private String token;
    private String newPassword;
}
