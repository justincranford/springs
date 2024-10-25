package com.github.justincranford.springs.persistenceorm.users.person;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

@Embeddable
class Address {
    @Column(length = 64, nullable = false)
    @NotNull
    private String street1;

    @Column(length = 64)
    @Null
    private String street2;

    @Column(length = 64, nullable = false)
    @NotNull
    private String city;

    @Column(length = 64, nullable = false)
    @NotNull
    private String state;

    @Column(length = 64, nullable = false)
    @NotNull
    private String country;

    @Enumerated(EnumType.STRING)
    @NotNull
    private AddressType type;
}