package com.github.justincranford.springs.persistenceorm.users.person;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;

@Embeddable
class Name {
    @Enumerated(EnumType.STRING)
    private Salutation salutation;

    @Column(nullable = false, length = 64)
    private String first;

    private String middle;

    private String last;

    private Suffix suffix;

    // Getters and Setters
}