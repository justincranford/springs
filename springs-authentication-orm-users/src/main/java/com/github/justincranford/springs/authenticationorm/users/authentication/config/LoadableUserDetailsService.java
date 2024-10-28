package com.github.justincranford.springs.authenticationorm.users.authentication.config;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.justincranford.springs.persistenceorm.users.person.EmailAddress;
import com.github.justincranford.springs.persistenceorm.users.person.EmailAddressRfc5321;
import com.github.justincranford.springs.persistenceorm.users.person.Language;
import com.github.justincranford.springs.persistenceorm.users.person.LocationAddress;
import com.github.justincranford.springs.persistenceorm.users.person.Name;
import com.github.justincranford.springs.persistenceorm.users.person.Password;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.person.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonaOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.person.PhoneNumber;
import com.github.justincranford.springs.persistenceorm.users.person.URL;

import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;

@Service
@SuppressWarnings({"nls"})
public class LoadableUserDetailsService implements UserDetailsService {
	@Autowired
    private PersonProperties personProperties;
    @Autowired
    private PersonOrmRepository personOrmRepository;
    @Autowired
    private PersonaOrmRepository personaOrmRepository;

	@Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        throw new UsernameNotFoundException("User not found");
    }

    @PostConstruct
    @Transactional
    public void loadUsers() {
        final List<PersonProperties.Person> users = this.personProperties.getUsers();
        
        for (final PersonProperties.Person user : users) {
            final PersonOrm createPersonOrm = new PersonOrm();
            createPersonOrm.username(user.getUsername());
            createPersonOrm.password(new Password(user.getPassword()));
            createPersonOrm.name(namePropertiesToOrm(user.getName()));
            createPersonOrm.dateOfBirth(user.getDateOfBirth());
            createPersonOrm.status(user.getStatus());
            createPersonOrm.languages(languagesPropertiesToOrm(user.getLanguages()));
            createPersonOrm.timezones(user.getTimezones());
            final PersonOrm createdPersonOrm = this.personOrmRepository.save(createPersonOrm);

            int rank = 0;
            for (PersonProperties.Person.Persona persona : user.getPersonas()) {
            	final PersonaOrm createPersonaOrm = new PersonaOrm();
                createPersonaOrm.rank(rank++);
                createPersonaOrm.emailAddresses(emailAddressesPropertiesToOrm(persona.getEmailAddresses()));
                createPersonaOrm.phoneNumbers(phoneNumberPropertiesToOrm(persona.getPhoneNumbers()));
                createPersonaOrm.locationAddresses(locationAddressPropertiesToOrm(persona.getLocationAddresses()));
                createPersonaOrm.urls(urlPropertiesToOrm(persona.getUrls()));
                createPersonaOrm.personaType(persona.getPersonaType());
                createPersonaOrm.person(createdPersonOrm); // Set back reference
                final PersonaOrm createdPersonaOrm = this.personaOrmRepository.save(createPersonaOrm);
                createdPersonOrm.personas().add(createdPersonaOrm); // TODO is this needed?
            }
        }
    }

    private static Name namePropertiesToOrm(PersonProperties.Person.Name nameProperties) {
		return Name.builder()
			.salutation(nameProperties.getSalutation())
			.first(nameProperties.getFirst())
			.middle(nameProperties.getMiddle())
			.last(nameProperties.getLast())
			.suffix(nameProperties.getSuffix())
			.build();
	}
    private static List<Language> languagesPropertiesToOrm(List<PersonProperties.Person.Language> languagesProperties) {
    	final AtomicInteger rank = new AtomicInteger(0);
    	return languagesProperties.stream()
    		.map(languageProperties ->
    			Language.builder()
					.rank(rank.getAndIncrement())
					.i18n(languageProperties.getI18n())
					.l10n(languageProperties.getL10n())
					.canSpeak(languageProperties.isCanSpeak())
					.canListen(languageProperties.isCanListen())
					.canRead(languageProperties.isCanRead())
					.canWrite(languageProperties.isCanWrite())
					.build()
    		)
    		.toList();
	}
    private static List<EmailAddress> emailAddressesPropertiesToOrm(List<PersonProperties.Person.Persona.EmailAddress> emailAddressesProperties) {
    	final AtomicInteger rank = new AtomicInteger(0);
    	return emailAddressesProperties.stream()
    		.map(emailAddressProperties ->
    			EmailAddress.builder()
    				.rank(rank.getAndIncrement())
					.emailAddress(new EmailAddressRfc5321(emailAddressProperties.getEmailAddress()))
					.type(emailAddressProperties.getType())
					.build()
    		)
    		.toList();
	}
    private static List<PhoneNumber> phoneNumberPropertiesToOrm(List<PersonProperties.Person.Persona.PhoneNumber> phoneNumbersProperties) {
    	final AtomicInteger rank = new AtomicInteger(0);
    	return phoneNumbersProperties.stream()
    		.map(phoneNumberProperties ->
    			PhoneNumber.builder()
    				.rank(rank.getAndIncrement())
					.phoneNumber(phoneNumberProperties.getPhoneNumber())
					.type(phoneNumberProperties.getType())
					.build()
    		)
    		.toList();
	}
    private static List<LocationAddress> locationAddressPropertiesToOrm(List<PersonProperties.Person.Persona.LocationAddress> locationAddresssProperties) {
    	final AtomicInteger rank = new AtomicInteger(0);
    	return locationAddresssProperties.stream()
    		.map(locationAddressProperties ->
    			LocationAddress.builder()
					.rank(rank.getAndIncrement())
					.street1(locationAddressProperties.getStreet1())
					.street2(locationAddressProperties.getStreet2())
					.city(locationAddressProperties.getCity())
					.state(locationAddressProperties.getState())
					.country(locationAddressProperties.getCountry())
					.type(locationAddressProperties.getType())
					.build()
    		)
    		.toList();
	}
    private static List<URL> urlPropertiesToOrm(List<PersonProperties.Person.Persona.URL> urlsProperties) {
    	final AtomicInteger rank = new AtomicInteger(0);
    	return urlsProperties.stream()
    		.map(urlProperties ->
    			URL.builder()
    				.rank(rank.getAndIncrement())
					.url(urlProperties.getUrl())
					.type(urlProperties.getType())
					.build()
    		)
    		.toList();
	}
}
