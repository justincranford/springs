package com.github.justincranford.springs.persistenceorm.users.person;

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
import org.springframework.lang.Nullable;

@Embeddable
@Getter(onMethod = @__(@JsonProperty))
@Setter
@ToString(callSuper = true, exclude = "password")
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent = true)
public class PasswordOrm {
    @PasswordConstraints
    @Column(length = 256)
    @Size(min = 12, max = 256)
    @Nullable
    private String password;
}
