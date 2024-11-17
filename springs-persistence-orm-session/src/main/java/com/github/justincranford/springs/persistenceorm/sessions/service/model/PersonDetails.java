package com.github.justincranford.springs.persistenceorm.sessions.service.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.PersonaType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Getter(onMethod = @__(@JsonProperty))
@Setter
@Builder
@Accessors(fluent = true)
@JsonIgnoreProperties({ "personOrm", "personaOrm" })
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class PersonDetails implements UserDetails {
    @Serial
    private static final long serialVersionUID = 1L;

    private String username; // personaOrm username

    private Long personId;

    private PersonOrm personOrm;

    private Long personaId;

    private PersonaOrm personaOrm;

    @Builder.Default
    private boolean accountNonExpired = true;

    @Builder.Default
    private boolean accountNonLocked = true;

    @Builder.Default
    private boolean credentialsNonExpired = true;

    @Builder.Default
    private boolean enabled = true;

    @Override
    public List<SimpleGrantedAuthority> getAuthorities() {
        if (this.personaOrm == null) {
            return List.of();
        }
        final PersonaType personaType = this.personaOrm.personaType();
        if (personaType == null) {
            return List.of();
        }
        return List.of(new SimpleGrantedAuthority("ROLE_" + personaType.name()));
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @SuppressWarnings("unused")
    public void setAuthorities(final List<SimpleGrantedAuthority> _authorities) {
        // do nothing
    }
}
