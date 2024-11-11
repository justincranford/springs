package com.github.justincranford.springs.persistenceorm.users.persona;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.EmailAddressType;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Embedded;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
public class EmailAddressOrm {
	@Column(nullable=false,columnDefinition="SMALLINT")
	private int rank;

	@Embedded
    private EmailAddressRfc5321Orm emailAddress;

    @Enumerated(EnumType.STRING)
    @Column(name="email_address_type",length=3,nullable=false,columnDefinition="CHAR(3)")
    @Size(min=3,max=3)
    @NotNull
	@NotBlank
    private EmailAddressType type;
}