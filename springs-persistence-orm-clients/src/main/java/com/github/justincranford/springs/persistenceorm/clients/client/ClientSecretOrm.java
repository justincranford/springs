package com.github.justincranford.springs.persistenceorm.clients.client;

import org.springframework.lang.Nullable;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraints;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
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
@ToString(exclude="secret")
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
public class ClientSecretOrm {
    @PasswordConstraints(minLength=43)
    @Column(length=86)
    @Size(min=43,max=86)
    @Nullable
    private String secret;
}
