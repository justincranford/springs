package com.github.justincranford.springs.authenticationorm.users.authentication.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.github.justincranford.springs.persistenceorm.sessions.service.model.PersonaDetails;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serial;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
@SuppressWarnings({"unused"})
public class PersonaEmailPasswordAuthenticatedToken extends AbstractAuthenticationToken {
    @Serial
    private static final long serialVersionUID = 1L;

    @Getter
    private final PersonaDetails personaDetails;

    @Setter
    private List<SimpleGrantedAuthority> authorities;

    public PersonaEmailPasswordAuthenticatedToken() {
        this(null);
    }

    public PersonaEmailPasswordAuthenticatedToken(final PersonaDetails _personaDetails) {
        super(_personaDetails == null ? null : _personaDetails.getAuthorities());
        super.setAuthenticated(true);
        this.personaDetails = _personaDetails;
        this.authorities = _personaDetails == null ? null : _personaDetails.getAuthorities();
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.personaDetails.getUsername(); // email address
    }

    @Override
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public List<GrantedAuthority> getAuthorities() {
        return (List) this.authorities;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (!isAuthenticated) {
            throw new UnsupportedOperationException("Set false is not supported in " + this.getClass().getSimpleName());
        }
        super.setAuthenticated(true);
    }

}
