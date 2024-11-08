package com.github.justincranford.springs.persistenceorm.clients.client;

import org.springframework.lang.Nullable;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.util.security.passwords.PasswordStrength;

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
@ToString(callSuper=true,exclude="password")
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
public class ClientPasswordOrm {
    @PasswordStrength(minLength=12)
    @Column(length=64)
    @Size(min=12,max=64)
    @Nullable
    private String password;
}
