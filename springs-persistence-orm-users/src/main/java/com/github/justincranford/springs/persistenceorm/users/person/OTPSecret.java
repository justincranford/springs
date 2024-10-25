package com.github.justincranford.springs.persistenceorm.users.person;

import java.time.OffsetDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

@Embeddable
class OTPSecret {
    @Column(nullable = false, unique = true, length = 40)
    private String secret;

    @Column(nullable = false)
    private OffsetDateTime expiresAt;

    private OffsetDateTime revokedAt;

    // Getters and Setters
}