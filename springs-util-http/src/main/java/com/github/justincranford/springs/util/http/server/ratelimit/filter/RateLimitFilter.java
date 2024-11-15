package com.github.justincranford.springs.util.http.server.ratelimit.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.justincranford.springs.util.http.server.ratelimit.properties.SpringsUtilHttpRateLimitProperties;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitFilter extends OncePerRequestFilter {
	@Autowired
	private SpringsUtilHttpRateLimitProperties springsAuthenticationOrmUsersRateLimitProperties;

    private Bucket bucket;

    @PostConstruct
    public void postConstruct() {
		if (this.springsAuthenticationOrmUsersRateLimitProperties.isEnabled()) {
    		final Bandwidth limit = Bandwidth.builder()
				.capacity(this.springsAuthenticationOrmUsersRateLimitProperties.getCapacity())
				.refillGreedy(this.springsAuthenticationOrmUsersRateLimitProperties.getRefillAmount(), this.springsAuthenticationOrmUsersRateLimitProperties.getRefillDuration())
				.build();
            log.debug("RateLimitFilter is enabled, bandwidth: {}", limit);
            this.bucket = Bucket.builder().addLimit(limit).build();
    	} else {
            log.trace("RateLimitFilter is disabled");
    	}
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    	if (this.springsAuthenticationOrmUsersRateLimitProperties.isEnabled()) {
    		final ConsumptionProbe probe = this.bucket.tryConsumeAndReturnRemaining(1);
    		if (!probe.isConsumed()) {
    			response.sendError(HttpStatus.TOO_MANY_REQUESTS.value());
    			final String retryAfterSeconds = String.valueOf(Math.ceil(probe.getNanosToWaitForRefill() / 1_000_000_000D));
				response.addHeader("X-Rate-Limit-Retry-After-Seconds", retryAfterSeconds);
                log.trace("X-Rate-Limit-Retry-After-Seconds: {}", retryAfterSeconds);
    			return;
    		}
    		final String remaining = String.valueOf(probe.getRemainingTokens());
            log.trace("X-Rate-Limit-Remaining: {}", remaining);
			response.addHeader("X-Rate-Limit-Remaining", remaining);
    	}
        filterChain.doFilter(request, response);
    }
}
