package com.github.justincranford.springs.util.observability.config;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Primary;

//import com.netflix.spectator.atlas.AtlasConfig;

//import io.micrometer.atlas.AtlasMeterRegistry;
import io.micrometer.core.aop.TimedAspect;
import io.micrometer.core.instrument.Clock;
import io.micrometer.core.instrument.ImmutableTag;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.composite.CompositeMeterRegistry;
import io.micrometer.core.instrument.logging.LoggingMeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
//import io.micrometer.prometheusmetrics.PrometheusConfig;
//import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableAspectJAutoProxy
//@ComponentScan(basePackages={"com.github.justincranford.springs.util.observability"})
@SuppressWarnings({"nls", "static-method"})
@Slf4j
public class SpringsUtilMeterRegistryConfiguration {
	@Autowired
	private ApplicationContext applicationContext;

	@Bean
	@Primary
	public MeterRegistry meterRegistry() {
		final CompositeMeterRegistry compositeMeterRegistry = new CompositeMeterRegistry(Clock.SYSTEM);
		compositeMeterRegistry.config().commonTags(metricsCommonTags());
		compositeMeterRegistry.add(new SimpleMeterRegistry());
		compositeMeterRegistry.add(new LoggingMeterRegistry());
//		compositeMeterRegistry.add(new AtlasMeterRegistry(atlasConfig()));
//		compositeMeterRegistry.add(new PrometheusMeterRegistry(prometheusConfig()));
		return compositeMeterRegistry;
	}

	@Bean
	public TimedAspect timedAspect(final MeterRegistry registry) {
		return new TimedAspect(registry);
	}

	private List<Tag> metricsCommonTags() {
		return List.of(
			new ImmutableTag("java.version", System.getProperty("java.version")),
			new ImmutableTag("spring.application.name", this.applicationContext.getId()),
			new ImmutableTag("spring.application.start", OffsetDateTime.ofInstant(Instant.ofEpochMilli(this.applicationContext.getStartupDate()), ZoneOffset.UTC).truncatedTo(ChronoUnit.NANOS).toString())
		);
	}

//	private AtlasConfig atlasConfig() {
//		return new AtlasConfig() {
//		    @Override
//		    public Duration step() {
//		        return Duration.ofSeconds(10);
//		    }
//		    @Override
//		    public Map<String, String> commonTags() {
//				return metricsCommonTags().stream().collect(Collectors.toMap(Tag::getKey, Tag::getValue));
//			}
//		    @Override
//		    public String get(String k) {
//		        return null; // accept the rest of the defaults
//		    }
//		};
//	}
//
//	private PrometheusConfig prometheusConfig() {
//		return new PrometheusConfig() {
//		    @Override
//		    public Duration step() {
//		        return Duration.ofSeconds(10);
//		    }
////		    @Override
////		    public Map<String, String> commonTags() {
////				return metricsCommonTags().stream().collect(Collectors.toMap(Tag::getKey, Tag::getValue));
////			}
//		    @Override
//		    public String get(String k) {
//		        return null; // accept the rest of the defaults
//		    }
//		};
//	}
}
