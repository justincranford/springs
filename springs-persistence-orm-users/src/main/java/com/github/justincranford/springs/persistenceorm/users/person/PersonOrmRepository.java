package com.github.justincranford.springs.persistenceorm.users.person;

import java.time.OffsetDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

public interface PersonOrmRepository extends ListCrudRepository<PersonOrm, Long>, RevisionRepository<PersonOrm, Long, Long> {
	Optional<PersonOrm> findByUsername(String username);

	// N.B. Include column aliases to match the method names inside PersonIdPasswordProjection
    @Query("SELECT p.id AS id,p.password.password AS personPassword FROM PersonOrm p WHERE p.username=:username")
    Optional<PersonProjectionIdPassword> findPersonProjectionIdPasswordByUsername(String username);

    @Modifying
    @Query("UPDATE PersonOrm p SET p.password.password=:password, p.lastModifiedDate=:now, p.preUpdateDateTime=:now, p.postUpdateDateTime=:now, p.version=p.version+1 WHERE p.id=:id")
    int updatePasswordById(Long id, String password, OffsetDateTime now);
}
