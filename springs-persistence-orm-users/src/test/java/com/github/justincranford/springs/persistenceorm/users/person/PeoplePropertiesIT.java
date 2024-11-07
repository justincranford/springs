package com.github.justincranford.springs.persistenceorm.users.person;

import java.util.List;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.persistenceorm.users.AbstractIT;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPeopleProperties;
import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPeopleProperties.Person;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public class PeoplePropertiesIT extends AbstractIT {
	@Test
	public void verifyPeoplePropertiesLoaded() {
		final List<Person> peopleProperties = peopleProperties().getPeople();
		Assertions.assertThat(peopleProperties).isNotNull();
		Assertions.assertThat(peopleProperties).isNotEmpty();
		Assertions.assertThat(peopleProperties).hasSize(3);
		for (final SpringsPersistenceOrmUsersPeopleProperties.Person personProperties : peopleProperties) {
			log.info("person: {}", personProperties);
			final List<SpringsPersistenceOrmUsersPeopleProperties.Person.Persona> personasProperties = personProperties.getPersonas();
			Assertions.assertThat(personasProperties).isNotNull();
			Assertions.assertThat(personasProperties).isNotEmpty();
			Assertions.assertThat(personasProperties).hasSize(1);
			for (final SpringsPersistenceOrmUsersPeopleProperties.Person.Persona personaProperties : personasProperties) {
				log.info("persona: {}", personaProperties);
				Assertions.assertThat(personaProperties).isNotNull();
			}
		}
	}

	@Test
	public void verifyPeopleOrmsLoaded() {
		final List<PersonOrm> personOrms = personOrmRepository().findAll();
		prettyJson().logAndSave(personOrms);
		Assertions.assertThat(personOrms).isNotNull();
		Assertions.assertThat(personOrms).isNotEmpty();
		Assertions.assertThat(personOrms).hasSize(3);
		for (final PersonOrm personOrm : personOrms) {
			prettyJson().logAndSave(personOrm);
			final List<PersonaOrm> personaOrms = personOrm.personas();
			prettyJson().logAndSave(personaOrms);
			Assertions.assertThat(personaOrms).isNotNull();
			Assertions.assertThat(personaOrms).isNotEmpty();
			Assertions.assertThat(personaOrms).hasSize(1);
			for (final PersonaOrm personaOrm : personaOrms) {
				prettyJson().logAndSave(personaOrm);
				Assertions.assertThat(personaOrm).isNotNull();
			}
		}
	}
}
