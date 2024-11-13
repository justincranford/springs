package com.github.justincranford.springs.authenticationorm.users.ratelimit.config;

import java.io.IOException;
import java.time.Duration;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class RateLimitingFilter extends OncePerRequestFilter {
	private static final boolean ENABLED = false;
    private static final int CAPACITY = 10000;
    private static final int REFILL_AMOUNT = 1000;
    private static final Duration REFILL_DURATION = Duration.ofSeconds(1);

    private Bucket bucket;

    @PostConstruct
    public void postConstruct() {
    	if (ENABLED) {
    		final Bandwidth limit = Bandwidth.builder().capacity(CAPACITY).refillGreedy(REFILL_AMOUNT, REFILL_DURATION).build();
            this.bucket = Bucket.builder().addLimit(limit).build();
    	}
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    	if (ENABLED) {
    		final ConsumptionProbe probe = this.bucket.tryConsumeAndReturnRemaining(1);
    		if (!probe.isConsumed()) {
    			final float waitForRefillNanos = probe.getNanosToWaitForRefill() / 1_000_000_000F;
    			response.addHeader("X-Rate-Limit-Retry-After-Seconds", String.valueOf(waitForRefillNanos));
    			response.sendError(HttpStatus.TOO_MANY_REQUESTS.value());
    			return;
    		}
    		response.addHeader("X-Rate-Limit-Remaining", String.valueOf(probe.getRemainingTokens()));
    	}
        filterChain.doFilter(request, response);
    }
}
