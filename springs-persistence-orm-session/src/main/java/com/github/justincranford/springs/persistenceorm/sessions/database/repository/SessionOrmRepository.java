package com.github.justincranford.springs.persistenceorm.sessions.database.repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.data.repository.query.Param;

import com.github.justincranford.springs.persistenceorm.sessions.database.entity.SessionOrm;

public interface SessionOrmRepository extends ListCrudRepository<SessionOrm, Long>, RevisionRepository<SessionOrm, Long, Long> {
	// SessionOrm

	Optional<SessionOrm> findByExternalId(@Param("externalId") byte[] externalId);

	@Query(nativeQuery=true,value="SELECT * FROM session s WHERE (s.max_inactive_interval > 0) AND (:now >= s.last_access_time) AND (pre_delete_date_time IS NULL OR pre_delete_date_time < CURRENT_TIMESTAMP) ORDER BY s.id")
	List<SessionOrm> findAllExpired(@Param("now") OffsetDateTime now);

	@Query(nativeQuery=true,value="SELECT * FROM session s WHERE (s.external_id = :externalId) ORDER BY s.pre_delete_date_time DESC NULLS FIRST LIMIT 1")
	Optional<SessionOrm> findByExternalIdIncludingDeleted(@Param("externalId") byte[] externalId);

	@Query(nativeQuery=true,value="SELECT * FROM session s WHERE (s.external_id = :externalId) ORDER BY s.pre_delete_date_time DESC NULLS FIRST")
	List<SessionOrm> findAllByExternalIdIncludingDeleted(@Param("externalId") byte[] externalId);

	@Query(nativeQuery=true,value="SELECT * FROM session s ORDER BY s.pre_delete_date_time DESC NULLS FIRST")
	List<SessionOrm> findAllIncludingDeleted();

	// Long
	
	@Query(nativeQuery=true,value="SELECT s.id FROM session s WHERE (s.external_id = :externalId) ORDER BY s.pre_delete_date_time DESC NULLS FIRST LIMIT 1")
	Optional<Long> findIdByExternalIdIncludingDeleted(@Param("externalId") byte[] externalId);

	@Query(nativeQuery=true,value="SELECT s.id FROM session s WHERE (s.external_id = :externalId) ORDER BY s.pre_delete_date_time DESC NULLS FIRST")
	List<Long> findAllIdByExternalIdIncludingDeleted(@Param("externalId") byte[] externalId);

	@Query(nativeQuery=true,value="SELECT s.id FROM session s ORDER BY s.pre_delete_date_time DESC NULLS FIRST")
	List<Long> findAllIdIncludingDeleted();
}