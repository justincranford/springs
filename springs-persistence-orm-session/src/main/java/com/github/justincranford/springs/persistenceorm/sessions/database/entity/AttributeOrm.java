package com.github.justincranford.springs.persistenceorm.sessions.database.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Lob;
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
@ToString(callSuper = true)
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent = true)
public class AttributeOrm {
    @Column(nullable = false, columnDefinition = "SMALLINT")
    private int rank;

    @Nullable
    @Column(columnDefinition = "TEXT")
    @Lob
    @Size(max = 1048576)
    private String encoded;
}
