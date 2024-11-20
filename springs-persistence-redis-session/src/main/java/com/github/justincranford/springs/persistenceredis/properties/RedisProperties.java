package com.github.justincranford.springs.persistenceredis.properties;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Component
@ConfigurationProperties(prefix="spring.redis",ignoreUnknownFields=false)
@Validated
@Getter
@Setter
@ToString
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class RedisProperties {
    @NotNull
    @Min(0)
    @Builder.Default
    private Integer database = 0;

    @NotEmpty
    @Builder.Default
    private String host = "localhost";

    @NotNull
    @Min(1)
    @Max(65535)
    @Builder.Default
    private Integer port = 6370;

    @NotNull
    @Builder.Default
    private String password = "";

    @NotNull
    @Builder.Default
    private Duration timeout = Duration.ofSeconds(5);
}
