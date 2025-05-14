package es.shehub.auth_service.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import es.shehub.auth_service.models.dtos.UserCreatedDTO;
import es.shehub.auth_service.models.dtos.UserRegisterRequestDTO;
import es.shehub.auth_service.models.entities.User;

@Mapper(componentModel = "spring")
public interface UserMapper {

    // From Register DTO to User entity
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "provider", ignore = true)
    @Mapping(target = "profileCompleted", constant = "false")
    @Mapping(target = "role", ignore = true) 
    User toUser(UserRegisterRequestDTO dto);

    // From User entity to UserCreatedDTO
    @Mapping(source = "id", target = "id")
    @Mapping(source = "role.name", target = "role")
    UserCreatedDTO toUserCreatedDTO(User user);
}
