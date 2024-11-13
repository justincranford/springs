package com.github.justincranford.springs.authenticationorm.users.ratelimit.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.justincranford.springs.authenticationorm.users.ratelimit.properties.SpringsAuthenticationOrmUsersRateLimitProperties;

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
	@Autowired
	private SpringsAuthenticationOrmUsersRateLimitProperties springsAuthenticationOrmUsersRateLimitProperties;

    private Bucket bucket;

    @PostConstruct
    public void postConstruct() {
    	if (this.springsAuthenticationOrmUsersRateLimitProperties.isEnabled()) {
    		final Bandwidth limit = Bandwidth.builder()
				.capacity(this.springsAuthenticationOrmUsersRateLimitProperties.getCapacity())
				.refillGreedy(this.springsAuthenticationOrmUsersRateLimitProperties.getRefillAmount(), this.springsAuthenticationOrmUsersRateLimitProperties.getRefillDuration())
				.build();
            this.bucket = Bucket.builder().addLimit(limit).build();
    	}
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    	if (this.springsAuthenticationOrmUsersRateLimitProperties.isEnabled()) {
    		final ConsumptionProbe probe = this.bucket.tryConsumeAndReturnRemaining(1);
    		if (!probe.isConsumed()) {
    			final double waitForRefillNanos = Math.ceil(probe.getNanosToWaitForRefill() / 1_000_000_000D);
    			response.addHeader("X-Rate-Limit-Retry-After-Seconds", String.valueOf(waitForRefillNanos));
    			response.sendError(HttpStatus.TOO_MANY_REQUESTS.value());
    			return;
    		}
    		response.addHeader("X-Rate-Limit-Remaining", String.valueOf(probe.getRemainingTokens()));
    	}
        filterChain.doFilter(request, response);
    }
}
