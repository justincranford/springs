package com.github.justincranford.springs.authenticationorm.users.authentication;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.justincranford.springs.persistenceorm.users.person.EmailAddressRfc5321;
import com.github.justincranford.springs.persistenceorm.users.person.Password;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonaOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonaType;

@Component
@SuppressWarnings({"nls"})
public class PersonaEmailPasswordAuthenticationProvider implements AuthenticationProvider {
    @Autowired private PersonaOrmRepository personaRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    private EmailAddressRfc5321.EmailConverter emailConverter = new EmailAddressRfc5321.EmailConverter(); 

	@Override
    public Authentication authenticate(final Authentication unauthenticated) throws AuthenticationException {
        String unauthenticatedEmail    = this.emailConverter.convertToDatabaseColumn(unauthenticated.getName());
        String unauthenticatedPassword = unauthenticated.getCredentials().toString();

        final Optional<PersonaOrm> personByEmailAddress = this.personaRepository.findPersonaByEmailAddress(unauthenticatedEmail);
		final PersonaOrm  persona        = personByEmailAddress.orElseThrow(() -> new PersonaEmailNotFoundException("Invalid email"));
		final String      personaEmail   = unauthenticatedEmail;
        final PersonaType personaType    = persona.personaType();
        final PersonOrm   person         = persona.person();
		final Password    personPassword = person.password();
		if (this.passwordEncoder.matches(unauthenticatedPassword, personPassword.password())) {
			return PersonaEmailPasswordAuthenticatedToken.authenticated(personaEmail, personPassword, List.of(new SimpleGrantedAuthority(personaType.name())));
        }
        throw new BadCredentialsException("Invalid password");
    }

    @Override
    public boolean supports(final Class<?> clazz) {
        return PersonaEmailPasswordAuthenticationProvider.class.equals(clazz);
    }
}
