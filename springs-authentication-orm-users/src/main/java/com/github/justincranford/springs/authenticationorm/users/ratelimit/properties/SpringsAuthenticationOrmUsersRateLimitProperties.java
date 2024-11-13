package com.github.justincranford.springs.authenticationorm.users.ratelimit.properties;
import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Component
@ConfigurationProperties(prefix="springs.authentication.orm.users", ignoreUnknownFields=false, ignoreInvalidFields=false)
@PropertySource("classpath:springs-authentication-orm-users.properties")
@Validated
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class SpringsAuthenticationOrmUsersRateLimitProperties {
	@Builder.Default
    private boolean enabled = true;

	@Builder.Default
    private int capacity = 10_000;

	@Builder.Default
    private int refillAmount = 1_000;

	@NotNull
	@Builder.Default
    private Duration refillDuration = Duration.ofSeconds(1);
}
