package com.github.justincranford.springs.persistenceorm.clients.client;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

import java.time.OffsetDateTime;
import java.util.Optional;

public interface ClientOrmRepository extends ListCrudRepository<ClientOrm, Long>, RevisionRepository<ClientOrm, Long, Long> {
    // N.B. Include column aliases to match the method names inside IdClientSecretProjection
    @Query("SELECT c.id AS id,c.clientSecret.clientSecret AS clientSecret FROM ClientOrm c WHERE c.clientId=:clientId")
    Optional<ClientProjectionIdSecret> findClientProjectionIdSecretByClientId(String clientId);

    @Modifying
    @Query("UPDATE ClientOrm c SET c.secret.secret=:secret, c.lastModifiedDate=:now, c.preUpdateDateTime=:now, c.postUpdateDateTime=:now, c.version=c.version+1 WHERE c.id=:id")
    int updateSecretById(Long id, String secret, OffsetDateTime now);
}
