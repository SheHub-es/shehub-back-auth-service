package es.shehub.auth_service.models.dtos.requests;

import java.util.HashSet;
import java.util.Set;

import es.shehub.auth_service.models.dtos.common.SchoolDTO;
import es.shehub.auth_service.models.dtos.common.SkillDTO;
import es.shehub.auth_service.models.dtos.common.TechRoleDTO;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class UpdateUserRequestDTO {
    private String firstName;
    private String lastName;
    private String avatarLink;
    private String linkedinLink;
    private String githubLink;
    private String portfolioLink;
    private int availabilityPerWeek;
    private String comments;

    private Set<TechRoleDTO> techRoles =  new HashSet<>();
    private Set<SkillDTO> skills =  new HashSet<>();
    private Set<SchoolDTO> schools =  new HashSet<>();
}
