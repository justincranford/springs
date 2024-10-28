package com.github.justincranford.springs.persistenceorm.users.person;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.users.person.enums.URLType;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.NotBlank;
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
public class UrlOrm {
	@Column(nullable=false,columnDefinition="TINYINT")
    private int rank;

    @Column(length=2048,nullable=false)
    @Size(min=8,max=2048) // http://a
    @NotNull
	@NotBlank
    private String url;

    @Enumerated(EnumType.STRING)
    @Column(name="url_type",length=16,nullable=false)
    @Size(min=2,max=16)
    @NotNull
	@NotBlank
    private URLType type;
}