package com.github.justincranford.springs.util.observability.meter.util;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@SuppressWarnings({ "unused", "static-method" })
@Slf4j
public class LogMeterRegistry {
    private static MeterRegistry METER_REGISTRY;
    @Autowired
    private MeterRegistry meterRegistry;

    @PostConstruct
    private void postConstruct() {
        METER_REGISTRY = this.meterRegistry;
    }

    @PreDestroy
    private void preDestroy() {
        assert METER_REGISTRY != null : "METER_REGISTRY must not be null";
        final List<Meter> meters = METER_REGISTRY.getMeters();
        if (meters.isEmpty()) {
            log.atInfo().log("No meters");
        } else {
            meters.forEach(meter -> log.atInfo().addArgument(() -> meter.getId()).addArgument(() -> meter.measure()).log("Meter: {} = {}"));
        }
    }
}
