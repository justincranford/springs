package com.github.justincranford.springs.persistenceorm.example.bushel;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

public interface BushelOrmRepository extends ListCrudRepository<BushelOrm, Long>, RevisionRepository<BushelOrm, Long, Long> {
	// do nothing
}