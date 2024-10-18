package com.github.justincranford.springs.persistenceorm.base.entity;

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
		entity.prePersistDateTime(DateTimeUtil.nowUtcTruncatedToMicroseconds());
		log.trace("prePersist entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PostPersist
	public void postPersist(final AbstractEntity entity) throws JsonProcessingException {
		entity.postPersistDateTime(DateTimeUtil.nowUtcTruncatedToMicroseconds());
		log.trace("postPersist entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PreUpdate
	public void preUpdate(final AbstractEntity entity) throws JsonProcessingException {
		entity.preUpdateDateTime(DateTimeUtil.nowUtcTruncatedToMicroseconds());
		log.trace("preUpdate entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PostUpdate
	public void postUpdate(final AbstractEntity entity) throws JsonProcessingException {
		entity.postUpdateDateTime(DateTimeUtil.nowUtcTruncatedToMicroseconds());
		log.trace("postUpdate entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PreRemove
	public void preDelete(final AbstractEntity entity) throws JsonProcessingException {
		entity.preDeleteDateTime(DateTimeUtil.nowUtcTruncatedToMicroseconds());
		log.trace("preDelete entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PostRemove
	public void postDelete(final AbstractEntity entity) throws JsonProcessingException {
		entity.postDeleteDateTime(DateTimeUtil.nowUtcTruncatedToMicroseconds());
		log.trace("postDelete entity: {}", this.objectMapper.writeValueAsString(entity));
	}
	@PostLoad
	public void postLoad(final AbstractEntity entity) throws JsonProcessingException {
		entity.postLoadDateTime(DateTimeUtil.nowUtcTruncatedToMicroseconds());
		log.trace("postLoad entity: {}", this.objectMapper.writeValueAsString(entity));
	}
}
