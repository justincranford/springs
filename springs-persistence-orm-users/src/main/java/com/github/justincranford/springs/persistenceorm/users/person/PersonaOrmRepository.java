package com.github.justincranford.springs.persistenceorm.users.person;

import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.data.repository.query.Param;

public interface PersonaOrmRepository extends ListCrudRepository<PersonaOrm, Long>, RevisionRepository<PersonaOrm, Long, Long> {
    @Query("SELECT po FROM PersonaOrm po JOIN po.emailAddresses ea WHERE ea.emailAddress = :emailAddress")
    Optional<PersonaOrm> findPersonaByEmailAddress(@Param("emailAddress") String emailAddress);

	@Query("SELECT p FROM PersonaOrm po JOIN po.person p JOIN po.emailAddresses ea WHERE ea.emailAddress = :emailAddress")
    Optional<PersonOrm> findPersonByEmailAddress(@Param("emailAddress") String emailAddress);

    @Query("SELECT p.password FROM PersonaOrm po JOIN po.person p JOIN po.emailAddresses ea WHERE ea.emailAddress = :emailAddress")
    Optional<PasswordOrm> findPasswordByEmailAddress(@Param("emailAddress") String emailAddress);
}