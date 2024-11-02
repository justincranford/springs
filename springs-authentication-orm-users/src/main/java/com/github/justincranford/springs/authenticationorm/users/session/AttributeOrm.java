package com.github.justincranford.springs.authenticationorm.users.session;

import org.springframework.lang.Nullable;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
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

	@Nullable
	@Column(length=1024)
	@Size(min=0,max=1024)
	private String encoded;
}