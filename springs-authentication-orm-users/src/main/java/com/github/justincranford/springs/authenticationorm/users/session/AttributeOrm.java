package com.github.justincranford.springs.authenticationorm.users.session;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
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

@Embeddable
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
public class AttributeOrm {
	@Column(nullable=false,columnDefinition="TINYINT")
	private int rank;

	@Column(nullable=false,updatable=false,length=64)
	@NotNull
	@NotBlank
	@Size(min=1,max=64)
	private String name;

	@Column
	private String value;

    @JsonBackReference
	@ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="session_id",foreignKey=@ForeignKey(name="fk_attribute_sessionid_2_session_id"))
    private SessionOrm person;
}