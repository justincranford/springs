package com.github.justincranford.springs.persistenceorm.users.person;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

public interface PersonOrmRepository extends ListCrudRepository<PersonOrm, Long>, RevisionRepository<PersonOrm, Long, Long> {
	// empty
}