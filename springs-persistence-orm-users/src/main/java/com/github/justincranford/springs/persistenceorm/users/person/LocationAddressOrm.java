package com.github.justincranford.springs.persistenceorm.users.person;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.users.person.enums.LocationAddressType;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
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
public class LocationAddressOrm {
	@Column(nullable=false,columnDefinition="TINYINT")
    private int rank;

    @Column(length=64,nullable=false)
    @NotNull
	@NotBlank
    private String street1;

    @Column(length=64)
//    @Null
    private String street2;

    @Column(length=64,nullable=false)
    @NotNull
	@NotBlank
    private String city;

    @Column(length=64,nullable=false)
    @NotNull
	@NotBlank
    private String state;

    @Column(length=64,nullable=false)
    @NotNull
	@NotBlank
    private String country;

    @Enumerated(EnumType.STRING)
    @Column(name="location_address_type",length=3,nullable=false,columnDefinition="CHAR(3)")
    @Size(min=3,max=3)
    @NotNull
	@NotBlank
    private LocationAddressType type;
}