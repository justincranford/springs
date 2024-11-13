package com.github.justincranford.springs.persistenceorm.users.persona;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.converter.LowercaseConverter;
import com.github.justincranford.springs.persistenceorm.users.persona.email.EmailRfc5321;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Embeddable;
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
public class EmailAddressRfc5321Orm {
	@EmailRfc5321 // N.B. applied before converter
	@Convert(converter=LowercaseConverter.class) // N.B. applied after validator
    @Column(length=254,nullable=false,unique=true) // RFCs 5321 & 5322
    @Size(min=3,max=254) // EX: 64 local @ 189 domain, 1 local @ 252 domain
    @NotNull
	@NotBlank
    private String emailAddress;
}
