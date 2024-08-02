package com.github.justincranford.springs.persistenceorm.example.entity;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.util.basic.DateTimeUtil;

import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.PostRemove;
import jakarta.persistence.PostUpdate;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreRemove;
import jakarta.persistence.PreUpdate;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@AllArgsConstructor
@Slf4j
@SuppressWarnings("nls")
public class EntityListener {
	private final ObjectMapper objectMapper;

	@PrePersist
	public void prePersist(final AbstractEntity entity) throws JsonProcessingException {
		entity.createDateTime(DateTimeUtil.nowUtcTruncatedToMilliseconds());
		log.info("prePersist entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PostPersist
	public void postPersist(final AbstractEntity entity) throws JsonProcessingException {
		entity.postCreateDateTime(DateTimeUtil.nowUtcTruncatedToMilliseconds());
		log.info("postPersist entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PreUpdate
	public void preUpdate(final AbstractEntity entity) throws JsonProcessingException {
		entity.updateDateTime(DateTimeUtil.nowUtcTruncatedToMilliseconds());
		log.info("preUpdate entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PostUpdate
	public void postUpdate(final AbstractEntity entity) throws JsonProcessingException {
		entity.postUpdateDateTime(DateTimeUtil.nowUtcTruncatedToMilliseconds());
		log.info("postUpdate entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PreRemove
	public void preDelete(final AbstractEntity entity) throws JsonProcessingException {
		entity.deleteDateTime(DateTimeUtil.nowUtcTruncatedToMilliseconds());
		log.info("preDelete entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PostRemove
	public void postDelete(final AbstractEntity entity) throws JsonProcessingException {
		entity.postDeleteDateTime(DateTimeUtil.nowUtcTruncatedToMilliseconds());
		log.info("postDelete entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PostLoad
	public void postLoad(final AbstractEntity entity) throws JsonProcessingException {
		entity.postLoadDateTime(DateTimeUtil.nowUtcTruncatedToMilliseconds());
		log.info("postLoad entity: {}", this.objectMapper.writeValueAsString(entity));
	}
//	@PostConstruct
//	public void postConstruct(final AbstractEntity entity) {
//		entity.postConstructDateTime(DateTimeUtil.nowUtcTruncatedToMilliseconds());
//		log.info("postConstruct entity: {}", this.objectMapper.writeValueAsString(entity));
//	}
}
