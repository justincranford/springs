package com.github.justincranford.springs.authenticationorm.users.authentication.config;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;

@Service
@SuppressWarnings({"nls"})
public class MyUserDetailsService implements UserDetailsService {
    @Autowired
    private PersonOrmRepository personOrmRepository;
    @Autowired
    private PersonaOrmRepository personaOrmRepository;

	@Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
		final Optional<PersonaOrm> optionalPersonaOrm = this.personaOrmRepository.findPersonaByEmailAddress(username);
		if (optionalPersonaOrm.isPresent()) {
			final PersonaOrm personaOrm = optionalPersonaOrm.get();
			final PersonOrm  personOrm  = personaOrm.person();
			return new PersonaDetails(true, personOrm.username(), personOrm, personaOrm);
		}

//		final Optional<PersonOrm> optionalPersonOrm = this.personOrmRepository.findByUsername(username);
//		if (optionalPersonOrm.isPresent()) {
//			final PersonOrm  personOrm = optionalPersonOrm.get();
//			final PersonaOrm personaOrm = personOrm.personas().get(0);
//			return new PersonaDetails(false, personOrm.username(), personOrm, personaOrm);
//		}

		throw new UsernameNotFoundException("User not found");
    }
}
