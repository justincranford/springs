package com.github.justincranford.springs.persistenceorm.users.person;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;

@Embeddable
class Language {

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private I18nLanguage i18n;  // Language code (e.g., en, fr, es)

    @Enumerated(EnumType.STRING)
    private L10nRegion l10n;  // Region/Locale code (e.g., US, CA, FR)

    @Column(nullable = false)
    private boolean talk;  // Can the person communicate via speech in this language?

    @Column(nullable = false)
    private boolean text;  // Can the person communicate via text in this language?

    // Getters and Setters
}