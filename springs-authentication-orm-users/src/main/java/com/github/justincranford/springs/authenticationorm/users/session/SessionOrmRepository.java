package com.github.justincranford.springs.authenticationorm.users.session;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

public interface SessionOrmRepository extends ListCrudRepository<SessionOrm, Long>, RevisionRepository<SessionOrm, Long, Long> {
	// empty
}