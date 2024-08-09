package com.github.justincranford.springs.persistenceorm.base.entity;

import java.time.OffsetDateTime;

import org.hibernate.envers.Audited;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.util.basic.util.DateTimeUtil;
import com.github.justincranford.springs.util.basic.util.SecureRandomUtil;

import jakarta.annotation.Nonnull;
import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.PostRemove;
import jakarta.persistence.PostUpdate;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreRemove;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Version;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@MappedSuperclass
@Audited // Hibernate Envers
@Getter(onMethod = @__(@JsonProperty)) // Jackson JSON
@Setter
@ToString(callSuper=false)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@EntityListeners(EntityListener.class)
@SuppressWarnings("nls")
@Slf4j
public class AbstractEntity {
	protected static final String WHERE_CLAUSE = "delete_date_time IS NULL OR delete_date_time < NOW()";
	protected static final int SEQUENCE_ID_INITIAL_VALUE = 1000;
	protected static final int SEQUENCE_ID_ALLOCATION_SIZE_SMALL = 10;
	protected static final int SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM = 100;
	protected static final int SEQUENCE_ID_ALLOCATION_SIZE_LARGE = 1000;
	protected static final int SEQUENCE_ID_ALLOCATION_SIZE_EXTRA_LARGE = 10000;
	protected static final String SEQUENCE_ID = "ABSTRACT_ENTITY_SEQUENCE_ID";

	@Id
    @GeneratedValue(strategy=GenerationType.SEQUENCE,generator=AbstractEntity.SEQUENCE_ID)
    private Long internalId;

    @Version
    @Column(nullable=false,insertable=false,columnDefinition="bigint default 0")
    private Long version;

	@Nonnull
	@NotNull
	@NotEmpty
	@Size(min=32,max=32)
    @Column(length=32,unique=true,nullable=false,updatable=false)
    private byte[] externalId;

	@Column(updatable=false,nullable=false)
	private OffsetDateTime createDateTime;

	@Column(insertable=false)
	private OffsetDateTime postCreateDateTime;

	@Column(insertable=false)
	private OffsetDateTime updateDateTime;

	@Column(insertable=false)
	private OffsetDateTime postUpdateDateTime;

	@Column(insertable=false)
	private OffsetDateTime deleteDateTime;

	@Column(insertable=false)
	private OffsetDateTime postDeleteDateTime;

	@Column(insertable=false)
	private OffsetDateTime postLoadDateTime;

	@PrePersist
	public void prePersist() {
		this.externalId = SecureRandomUtil.staticRandomBytes(32);
		this.createDateTime = DateTimeUtil.nowUtcTruncatedToMilliseconds();
	}
	@PostPersist
	public void postPersist() {
		this.postCreateDateTime = DateTimeUtil.nowUtcTruncatedToMilliseconds();
	}
	@PreUpdate
	public void preUpdate() {
		this.updateDateTime = DateTimeUtil.nowUtcTruncatedToMilliseconds();
	}
	@PostUpdate
	public void postUpdate() {
		this.postUpdateDateTime = DateTimeUtil.nowUtcTruncatedToMilliseconds();
	}
	@PreRemove
	public void preDelete() {
		this.deleteDateTime = DateTimeUtil.nowUtcTruncatedToMilliseconds();
	}
	@PostRemove
	public void postDelete() {
		this.postDeleteDateTime = DateTimeUtil.nowUtcTruncatedToMilliseconds();
	}
	@PostLoad
	public void postLoad() {
		this.postLoadDateTime = DateTimeUtil.nowUtcTruncatedToMilliseconds();
	}

	@Override
    public final boolean equals(Object o) {
		return (this == o) || ( (this.getClass().equals(o.getClass())) && (this.internalId == ((AbstractEntity)o).internalId) );
    }

    @Override
    public final int hashCode() {
        return this.getClass().hashCode();
    }
}
