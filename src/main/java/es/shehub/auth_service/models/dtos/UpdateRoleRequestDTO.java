package es.shehub.auth_service.models.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class UpdateRoleRequestDTO {
    private final String roleName;
}
