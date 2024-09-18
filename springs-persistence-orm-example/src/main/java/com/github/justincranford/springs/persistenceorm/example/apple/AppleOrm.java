package com.github.justincranford.springs.persistenceorm.example.apple;

import java.util.Arrays;
import java.util.List;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;
import org.springframework.lang.NonNull;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.example.bushel.BushelOrm;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Entity
@Audited
@Table(name="apple")
@Getter(onMethod=@__(@JsonProperty))
@Setter
@JsonIgnoreProperties(value={"bushel"})
@ToString(callSuper=true,exclude="bushel")
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE apple SET pre_delete_date_time=NOW() WHERE internal_id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="apple_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
@SuppressWarnings("nls")
public class AppleOrm extends AbstractEntity {
	public enum Type {
		EMPIRE, GALA, GOLDEN_DELICIOUS;
		public static final int MIN_LENGTH = 4; // "GALA"
		public static final int MAX_LENGTH = 16; // "GOLDEN_DELICIOUS"
	}

	static {
		final List<Integer> lengths = Arrays.stream(Type.values()).map(e->Integer.valueOf(e.name().length())).toList();
		final int actualMinLength = lengths.stream().min(Integer::compare).get().intValue();
		final int actualMaxLength = lengths.stream().max(Integer::compare).get().intValue();
		assert Type.MIN_LENGTH == actualMinLength : "Expected MIN_LENGTH " + Type.MIN_LENGTH + " does not match actual " + actualMinLength;
		assert Type.MAX_LENGTH == actualMaxLength : "Expected MAX_LENGTH " + Type.MAX_LENGTH + " does not match actual " + actualMaxLength;
	}

	@Column(length=Type.MAX_LENGTH,nullable=false)
	@Enumerated(EnumType.STRING)
	@NonNull
	private Type type;
  
	@Column(length=255,nullable=false)
	@Size(min=0,max=255)
	@NonNull
	@Builder.Default
	private String description = "";

	@ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="bushel_id",foreignKey=@ForeignKey(name="fk_apple_bushelid_2_bushel_id"))
    private BushelOrm bushel;
}