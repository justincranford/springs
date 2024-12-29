package com.github.justincranford.springs.persistenceorm.clients.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.clients.client.enums.ClientStatusType;
import com.github.justincranford.springs.persistenceorm.clients.client.enums.ClientType;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OrderColumn;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;

import java.util.ArrayList;
import java.util.List;

@Entity
@Audited
@Table(name="client")
@SQLDelete(sql="UPDATE client SET pre_delete_date_time=CURRENT_TIMESTAMP WHERE internal_id=? AND version=?")
@SQLRestriction(AbstractEntity.SQL_WHERE_CLAUSE)
@SequenceGenerator(sequenceName="client_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
@Getter(onMethod=@__(@JsonProperty))
@Setter
@Accessors(fluent=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper=true,exclude="secret")
public class ClientOrm extends AbstractEntity {
    @Column(length=64,nullable=false,unique=true)
	@Size(min=10,max=64)
	@NotNull
	@NotBlank
    private String name;

    @Embedded
    private ClientSecretOrm secret;

    @Enumerated(EnumType.STRING)
    @Column(nullable=false,length=3)
    @NotNull
    private ClientStatusType status;

    @Enumerated(EnumType.STRING)
    @Column(nullable=false,length=3)
    @NotNull
    private ClientType clientType;

    @ElementCollection
    @CollectionTable(
		name="client_timezones",
    	joinColumns=@JoinColumn(name="clientInternalId",referencedColumnName="internalId"),
    	foreignKey=@ForeignKey(name = "fk_client_timezones_client_internal_id"),
    	indexes= {@Index(name="idx_client_timezones_client_internal_id_rank",columnList="client_internal_id,rank")}
    )
    @OrderColumn(name="rank")
    @NotNull
    @Size(max=4)
    @Builder.Default
    private List<@NotNull String> clientTimeZones = new ArrayList<>(1);
}
