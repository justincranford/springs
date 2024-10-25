package com.github.justincranford.springs.persistenceorm.users.person;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

public interface PersonaOrmRepository extends ListCrudRepository<PersonaOrm, Long>, RevisionRepository<PersonaOrm, Long, Long> {
	// empty
}