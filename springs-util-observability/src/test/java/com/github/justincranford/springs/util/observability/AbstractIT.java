package com.github.justincranford.springs.util.observability;

import com.github.justincranford.springs.util.observability.config.SpringsUtilObservabilityConfiguration;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.Getter;
import lombok.experimental.Accessors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(classes = { SpringsUtilObservabilityConfiguration.class, AbstractIT.AbstractITConfiguration.class })
@AutoConfigureObservability
@Getter
@Accessors(fluent = true)
@ActiveProfiles({ "test" })
@SuppressWarnings({"unused"})
public class AbstractIT {
    @Autowired
    private MeterRegistry meterRegistry;

    @Configuration
    @EnableAutoConfiguration
    public static class AbstractITConfiguration {
        // do nothing
    }
}
