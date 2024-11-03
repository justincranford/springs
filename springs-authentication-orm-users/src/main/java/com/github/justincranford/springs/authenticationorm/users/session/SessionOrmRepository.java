package com.github.justincranford.springs.authenticationorm.users.session;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.data.repository.query.Param;

import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;

public interface SessionOrmRepository extends ListCrudRepository<SessionOrm, Long>, RevisionRepository<SessionOrm, Long, Long> {
	Optional<SessionOrm> findByExternalId(byte[] externalId);

	@Query("SELECT s FROM SessionOrm s WHERE (s.externalId = :externalId) AND (s.preDeleteDateTime IS NULL OR s.preDeleteDateTime < CURRENT_TIMESTAMP)")
	List<SessionOrm> findAllByExternalId(@Param("externalId") byte[] externalId);

	@Query("SELECT s.id FROM SessionOrm s WHERE (s.externalId = :externalId) AND (s.preDeleteDateTime IS NULL OR s.preDeleteDateTime < CURRENT_TIMESTAMP)")// + AbstractEntity.JPDL_WHERE_CLAUSE)
	Optional<Long> findIdByExternalId(@Param("externalId") byte[] externalId);
}