package com.github.justincranford.springs.persistenceorm.clients.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrm;
import com.github.justincranford.springs.persistenceorm.clients.client.enums.ClientType;
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
@Getter(onMethod=@__(@JsonProperty))
@Setter
@Builder
@Accessors(fluent=true)
@JsonIgnoreProperties({"clientOrm"})
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class ClientDetails implements UserDetails {
	@Serial
	private static final long serialVersionUID = 1L;

	private String clientClientName;

	private Long clientName;

	private ClientOrm clientOrm;

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
		return this.clientClientName;
	}

	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public List<SimpleGrantedAuthority> getAuthorities() {
		if (this.clientOrm == null) {
			return List.of();
		}
		final ClientType clientType = this.clientOrm.clientType();
        assert clientType != null;
        return List.of(new SimpleGrantedAuthority("ROLE_" + clientType.name()));
	}

	@SuppressWarnings("unused")
	public void setAuthorities(final List<SimpleGrantedAuthority> _authorities) {
		// do nothing
	}
}
