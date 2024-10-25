package com.github.justincranford.springs.persistenceorm.users.person;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;

@Embeddable
class Email {
//    @Email
    @Column(nullable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    private EmailType type;

    // Getters and Setters
}