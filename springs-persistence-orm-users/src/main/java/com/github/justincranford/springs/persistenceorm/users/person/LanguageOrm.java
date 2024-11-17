package com.github.justincranford.springs.persistenceorm.users.person;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.users.person.enums.I18nLanguageType;
import com.github.justincranford.springs.persistenceorm.users.person.enums.L10nRegionType;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
@Getter(onMethod = @__(@JsonProperty))
@Setter
@ToString(callSuper = true)
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent = true)
public class LanguageOrm {
    @Column(nullable = false, columnDefinition = "SMALLINT")
    private int rank;

    @Enumerated(EnumType.STRING)
    @Column(length = 3, nullable = false, columnDefinition = "CHAR(3)")
    @Size(min = 2, max = 3)
    @NotNull
    private I18nLanguageType i18n;

    @Enumerated(EnumType.STRING)
    @Column(length = 3, nullable = false, columnDefinition = "CHAR(3)")
    @Size(min = 2, max = 3)
    @NotNull
    private L10nRegionType l10n;

    @Column(nullable = false)
    @NotNull
    private boolean canSpeak;

    @Column(nullable = false)
    @NotNull
    private boolean canListen;

    @Column(nullable = false)
    private boolean canRead;

    @Column(nullable = false)
    private boolean canWrite;
}
