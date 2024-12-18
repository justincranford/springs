package com.github.justincranford.springs.persistenceorm.users.persona.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Getter(onMethod=@__(@JsonProperty))
@Setter
@Builder
@Accessors(fluent=true)
@JsonIgnoreProperties({"personOrm", "personaOrm"})
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class PersonaDetails implements UserDetails {
	@Serial
	private static final long serialVersionUID = 1L;
	private String username; // 1-of-N email addresses in personaOrm that matched

	private Long personId;

	private Long personaId;

	@Builder.Default
	private List<SimpleGrantedAuthority> authorities = new ArrayList<>(1);

	@Builder.Default
	private boolean accountNonExpired = true;

	@Builder.Default
	private boolean accountNonLocked = true;

	@Builder.Default
	private boolean credentialsNonExpired = true;

	@Builder.Default
	private boolean enabled = true;

	@Override
	public String getUsername() {
		return this.username;
	}

	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public List<SimpleGrantedAuthority> getAuthorities() {
		return this.authorities == null ? List.of() : List.copyOf(this.authorities);

	}
}
