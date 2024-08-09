package com.github.justincranford.springs.util.observability.config;

import org.springframework.stereotype.Component;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
@SuppressWarnings({"nls", "static-method"})
public class TraceObservationHandler implements ObservationHandler<Observation.Context> {
	@Override
    public void onStart(final Observation.Context context) {
        log.info("Before running the observation for context [{}], userType [{}]", context.getName());
    }

    @Override
    public void onStop(final Observation.Context context) {
        log.info("After running the observation for context [{}], userType [{}]", context.getName());
    }

    @Override
    public boolean supportsContext(final Observation.Context context) {
        return true;
    }
}