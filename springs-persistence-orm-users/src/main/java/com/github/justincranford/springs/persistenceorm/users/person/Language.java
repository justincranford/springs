package com.github.justincranford.springs.persistenceorm.users.person;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.users.person.enums.I18nLanguage;
import com.github.justincranford.springs.persistenceorm.users.person.enums.L10nRegion;

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
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
class Language {
    @Enumerated(EnumType.STRING)
    @Column(length=2,nullable=false,columnDefinition="CHAR(2)")
    @Size(min=2,max=2)
    @NotNull
    private I18nLanguage i18n;

    @Enumerated(EnumType.STRING)
    @Column(length=2,nullable=false,columnDefinition="CHAR(2)")
    @Size(min=2,max=2)
    @NotNull
    private L10nRegion l10n;

    @Column(nullable=false)
    @NotNull
    private boolean canSpeak;

    @Column(nullable=false)
    @NotNull
    private boolean canListen;

    @Column(nullable=false)
    private boolean canRead;

    @Column(nullable=false)
    private boolean canWrite;
}