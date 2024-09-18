package com.github.justincranford.springs.persistenceorm.example.bushel;

import java.util.HashSet;
import java.util.Set;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;
import org.springframework.lang.NonNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.example.apple.AppleOrm;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.OneToMany;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Entity
@Audited
@Table(name="bushel")
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE bushel SET pre_delete_date_time=NOW() WHERE internal_id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
//@FilterDef(name="isNotDeletedBushelFilter", parameters=@ParamDef(name="deleteDateTime",type=OffsetDateTime.class))
//@FilterDef(name="isDeletedBushelFilter", parameters=@ParamDef(name="deleteDateTime",type=OffsetDateTime.class))
//@Filter(name="isNotDeletedBushelFilter", condition="deleted=:(deleteDateTime IS NULL) OR (deleteDateTime < NOW())")
//@Filter(name="isDeletedBushelFilter", condition="deleted=:(deleteDateTime IS NOT NULL) AND (NOW() <= deleteDateTime)")
@SequenceGenerator(sequenceName="bushel_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_SMALL)
public class BushelOrm extends AbstractEntity {
	@OneToMany(mappedBy="bushel",cascade=CascadeType.ALL,orphanRemoval=true,fetch=FetchType.LAZY)
//	@JoinColumn(name="bushel_id")
	@NonNull
	@Builder.Default
	private Set<AppleOrm> apples = new HashSet<>();

	public void addApple(AppleOrm apple) {
        this.apples.add(apple);
        apple.bushel(this);
    }
 
    public void removeApple(AppleOrm apple) {
    	this.apples.remove(apple);
        apple.bushel(null);
    }
}