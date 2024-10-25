package com.github.justincranford.springs.persistenceorm.users.person;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.users.person.enums.LocationAddressType;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
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
class LocationAddress {
    @Column(length=64,nullable=false)
    @NotNull
    private String street1;

    @Column(length=64)
    @Null
    private String street2;

    @Column(length=64,nullable=false)
    @NotNull
    private String city;

    @Column(length=64,nullable=false)
    @NotNull
    private String state;

    @Column(length=64,nullable=false)
    @NotNull
    private String country;

    @Enumerated(EnumType.STRING)
    @Column(name="location_address_type",nullable=false,columnDefinition="VARCHAR(3)")
    @NotNull
    private LocationAddressType type;
}