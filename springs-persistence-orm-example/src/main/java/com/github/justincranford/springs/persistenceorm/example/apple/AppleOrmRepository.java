package com.github.justincranford.springs.persistenceorm.example.apple;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

import java.util.List;

@SuppressWarnings({ "unused" })
public interface AppleOrmRepository extends ListCrudRepository<AppleOrm,Long>, RevisionRepository<AppleOrm,Long,Long> {
    List<AppleOrm> findByType(AppleOrm.Type type);

    List<AppleOrm> findByDescription(String description);

    List<AppleOrm> findByDescriptionIgnoreCase(String description);

    List<AppleOrm> findByDescriptionStartsWith(String description);

    List<AppleOrm> findByDescriptionEndsWith(String description);

    List<AppleOrm> findByDescriptionContaining(String description);

    List<AppleOrm> findByDescriptionLike(String description);

    List<AppleOrm> findByDescriptionNotLike(String description);

    List<AppleOrm> findByTypeAndDescription(AppleOrm.Type type, String description);

    List<AppleOrm> findByTypeAndDescriptionIgnoreCase(AppleOrm.Type type, String description);

    List<AppleOrm> findByTypeAndDescriptionStartsWith(AppleOrm.Type type, String description);

    List<AppleOrm> findByTypeAndDescriptionEndsWith(AppleOrm.Type type, String description);

    List<AppleOrm> findByTypeAndDescriptionContaining(AppleOrm.Type type, String description);

    List<AppleOrm> findByTypeAndDescriptionLike(AppleOrm.Type type, String description);

    List<AppleOrm> findByTypeAndDescriptionNotLike(AppleOrm.Type type, String description);
}
