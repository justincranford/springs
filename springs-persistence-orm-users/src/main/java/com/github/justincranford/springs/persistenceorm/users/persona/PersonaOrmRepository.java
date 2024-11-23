package com.github.justincranford.springs.persistenceorm.users.persona;

import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;

public interface PersonaOrmRepository extends ListCrudRepository<PersonaOrm, Long>, RevisionRepository<PersonaOrm, Long, Long> {
    @Query("SELECT po FROM PersonaOrm po JOIN po.emailAddresses ea WHERE ea.emailAddress.emailAddress=:emailAddress")
    Optional<PersonaOrm> findByEmailAddress(String emailAddress);

	@Query("SELECT p FROM PersonaOrm po JOIN po.person p JOIN po.emailAddresses ea WHERE ea.emailAddress.emailAddress=:emailAddress")
    Optional<PersonOrm> findPersonByEmailAddress(String emailAddress);

	// N.B. Include column aliases to match the method names inside PersonaIdAndPersonIdPasswordProjection
    @Query("SELECT po.id AS id,p.id AS personId,p.password.password AS personPassword FROM PersonaOrm po JOIN po.emailAddresses ea JOIN po.person p WHERE ea.emailAddress.emailAddress=:emailAddress")
    Optional<PersonaProjectionIdAndPersonIdPassword> findPersonaIdAndPersonIdAndPasswordByEmailAddress(String emailAddress);
}
