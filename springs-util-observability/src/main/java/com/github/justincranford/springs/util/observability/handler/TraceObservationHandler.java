package com.github.justincranford.springs.util.observability.handler;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class TraceObservationHandler implements ObservationHandler<Observation.Context> {
    @Override
    public void onStart(final Observation.Context context) {
        log.trace("Before running the observation for context [{}]", context.getName());
    }

    @Override
    public void onStop(final Observation.Context context) {
        log.trace("After running the observation for context [{}]", context.getName());
    }

    @Override
    public boolean supportsContext(final Observation.Context context) {
        return true;
    }
}
