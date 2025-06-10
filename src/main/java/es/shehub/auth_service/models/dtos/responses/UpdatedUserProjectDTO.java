package es.shehub.auth_service.models.dtos.responses;

import java.util.HashSet;
import java.util.Set;

import es.shehub.auth_service.models.dtos.common.SchoolDTO;
import es.shehub.auth_service.models.dtos.common.SkillDTO;
import es.shehub.auth_service.models.dtos.common.TechRoleDTO;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UpdatedUserProjectDTO {
    private String firstName;
    private String lastName;
    private String avatarLink;
    private String linkedinLink;
    private String githubLink;
    private String portfolioLink;
    private int availabilityPerWeek;
    private String comments;
    private boolean teamLead;

    private Set<TechRoleDTO> techRoles =  new HashSet<>();
    private Set<SkillDTO> skills =  new HashSet<>();
    private Set<SchoolDTO> schools =  new HashSet<>();
}
