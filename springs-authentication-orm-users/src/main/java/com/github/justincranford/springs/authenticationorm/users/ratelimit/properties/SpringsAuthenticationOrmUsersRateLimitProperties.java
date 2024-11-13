package com.github.justincranford.springs.authenticationorm.users.ratelimit.properties;
import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
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

	@Positive
	@Builder.Default
    private int capacity = LOW_PRECISION.getCapacity();

	@Positive
	@Builder.Default
    private int refillAmount = LOW_PRECISION.getRefillAmount();

	@NotNull
	@Builder.Default
    private Duration refillDuration = LOW_PRECISION.getRefillDuration();

	private static final int PER_MINUTE = 150 * 60; // target rate is 150/sec, converted to minutes
	private static final int CAPACITY_MULTIPLIER = 10; // target max is 1500 (i.e. 10x burst before throttle)

	/** More precision (i.e. 200msec). Real-time control, but higher CPU/memory overhead. Smooth for high freq. */
	public static final SpringsAuthenticationOrmUsersRateLimitProperties HIGH_PRECISION = SpringsAuthenticationOrmUsersRateLimitProperties.builder()
		.enabled(true).refillDuration(Duration.ofMillis(200)).refillAmount(PER_MINUTE * 60 * 5).capacity(PER_MINUTE * 60 * 5 * CAPACITY_MULTIPLIER).build();

	/** Balanced precision (i.e. 1 sec). Near real-time control, with medium CPU/memory overheard. Smooth for medium freq. */
	public static final SpringsAuthenticationOrmUsersRateLimitProperties MEDIUM_PRECISION = SpringsAuthenticationOrmUsersRateLimitProperties.builder()
		.enabled(true).refillDuration(Duration.ofSeconds(1)).refillAmount(PER_MINUTE * 60).capacity(PER_MINUTE * 60 * CAPACITY_MULTIPLIER).build();

	/** Less precision (i.e. 1 min). Delayed control, with low CPU/memory overheard. Smooth for low freq. */
	public static final SpringsAuthenticationOrmUsersRateLimitProperties LOW_PRECISION = SpringsAuthenticationOrmUsersRateLimitProperties.builder()
		.enabled(true).refillDuration(Duration.ofMinutes(1)).refillAmount(PER_MINUTE).capacity(PER_MINUTE * CAPACITY_MULTIPLIER).build();

	/** Disabled. No CPU/Memory overhead. */
	public static final SpringsAuthenticationOrmUsersRateLimitProperties DISABLED = SpringsAuthenticationOrmUsersRateLimitProperties.builder()
		.enabled(false).capacity(1).refillAmount(1).refillDuration(Duration.ofNanos(1)).build();
}
