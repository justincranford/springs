package com.github.justincranford.springs.persistenceorm.users.person;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PhoneNumberType;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
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
class PhoneNumber {
	@Pattern(regexp = "^\\+?[1-9]\\d{1,14}$", message = "Phone number must be in valid E.164 format. Optional + prefix, non-zero first digit, 1-15 digits total.")
    @Column(length=16,nullable=false)
	@Size(min=8,max=16) // +, then a non-zero digit, then up to 14 additional digits
    private String phoneNumber;

    @Enumerated(EnumType.STRING)
    @Column(name="phone_number_type",length=16,nullable=false)
	@Size(min=2,max=16)
    @NotNull
    private PhoneNumberType type;
}