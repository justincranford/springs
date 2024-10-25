package com.github.justincranford.springs.persistenceorm.users.person;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PhoneNumberType;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
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
class PhoneNumbersOrm {
    @Pattern(regexp = "\\+?[0-9]*")
    @Column(nullable = false)
    private String phoneNumber;

    @Column(nullable = false)
    private String countryCode;

    @Enumerated(EnumType.STRING)
    @Column(name="phone_number_type",nullable=false,columnDefinition="VARCHAR(13)")
    @NotNull
    private PhoneNumberType type;
}