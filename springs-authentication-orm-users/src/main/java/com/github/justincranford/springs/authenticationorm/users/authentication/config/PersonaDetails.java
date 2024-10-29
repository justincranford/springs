package com.github.justincranford.springs.authenticationorm.users.authentication.config;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.PersonaType;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;

@RequiredArgsConstructor
@Getter
@Accessors(fluent=true)
public class PersonaDetails implements UserDetails {
	private static final long serialVersionUID = 1L;
	private final boolean foundByPersona;
	private final String personaEmailAddressOrPersonUsername;
	private final PersonOrm personOrm;
	private final PersonaOrm personaOrm;
	@Override
	public String getUsername() {
		return this.personaEmailAddressOrPersonUsername;
	}
	@Override
	public String getPassword() {
		return this.personOrm.password().password();
	}
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		final PersonaType personaType = this.personaOrm.personaType();
		return List.of(new SimpleGrantedAuthority(personaType.name()));
	}
}
