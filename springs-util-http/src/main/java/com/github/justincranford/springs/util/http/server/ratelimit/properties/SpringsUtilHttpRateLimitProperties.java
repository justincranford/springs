package com.github.justincranford.springs.util.http.server.ratelimit.properties;
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
@ConfigurationProperties(prefix="springs.util.http.rate-limit", ignoreUnknownFields=false, ignoreInvalidFields=false)
@PropertySource("classpath:springs-util-http-rate-limit.properties")
@Validated
@Getter
@Setter
@ToString(callSuper=false)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
public class SpringsUtilHttpRateLimitProperties {
	private static final int TARGET_RATE_PER_MINUTE = 150 * 60; // target rate is 150/sec, converted to minutes
	private static final int TARGET_CAPACITY_MULTIPLIER = 5; // target max is 750 (i.e. 5x before throttle)

	/** More precision (i.e. 200msec). Real-time control, but higher CPU/memory overhead. Smooth for high freq. */
	public static final SpringsUtilHttpRateLimitProperties HIGH_PRECISION = SpringsUtilHttpRateLimitProperties.builder()
		.enabled(true).refillDuration(Duration.ofMillis(200)).refillAmount(TARGET_RATE_PER_MINUTE / 60 / 5).capacity(TARGET_RATE_PER_MINUTE / 60 / 5 * TARGET_CAPACITY_MULTIPLIER).build();

	/** Balanced precision (i.e. 1 sec). Near real-time control, with medium CPU/memory overheard. Smooth for medium freq. */
	public static final SpringsUtilHttpRateLimitProperties MEDIUM_PRECISION = SpringsUtilHttpRateLimitProperties.builder()
		.enabled(true).refillDuration(Duration.ofSeconds(1)).refillAmount(TARGET_RATE_PER_MINUTE / 60).capacity(TARGET_RATE_PER_MINUTE / 60 * TARGET_CAPACITY_MULTIPLIER).build();

	/** Less precision (i.e. 1 min). Delayed control, with low CPU/memory overheard. Smooth for low freq. */
	public static final SpringsUtilHttpRateLimitProperties LOW_PRECISION = SpringsUtilHttpRateLimitProperties.builder()
		.enabled(true).refillDuration(Duration.ofMinutes(1)).refillAmount(TARGET_RATE_PER_MINUTE).capacity(TARGET_RATE_PER_MINUTE * TARGET_CAPACITY_MULTIPLIER).build();

	/** Disabled. No CPU/Memory overhead. */
	public static final SpringsUtilHttpRateLimitProperties DISABLED = SpringsUtilHttpRateLimitProperties.builder()
		.enabled(false).capacity(1).refillAmount(1).refillDuration(Duration.ofNanos(1)).build();

	public static final SpringsUtilHttpRateLimitProperties DEFAULT = LOW_PRECISION;

	@Builder.Default
    private boolean enabled = DEFAULT.isEnabled();

	@Positive
	@Builder.Default
    private int capacity = DEFAULT.getCapacity();

	@Positive
	@Builder.Default
    private int refillAmount = DEFAULT.getRefillAmount();

	@NotNull
	@Builder.Default
    private Duration refillDuration = DEFAULT.getRefillDuration();
}
