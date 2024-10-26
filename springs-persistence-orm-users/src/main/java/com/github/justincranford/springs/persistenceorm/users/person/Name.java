package com.github.justincranford.springs.persistenceorm.users.person;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.users.person.enums.Salutation;
import com.github.justincranford.springs.persistenceorm.users.person.enums.Suffix;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
class Name {
    @Enumerated(EnumType.STRING)
    @Column(length=64)
    @Size(min=2,max=64)
    @Null
    private Salutation salutation;

    @Column(length=64,nullable=false)
    @NotNull
    private String first;

    @Column(length=64)
    @Null
    private String middle;

    @Column(length=64)
    @Null
    private String last;

    @Enumerated(EnumType.STRING)
    @Column(length=5)
    @Size(min=1,max=5)
    @Null
    private Suffix suffix;
}