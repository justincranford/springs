package com.github.justincranford.springs.util.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;

import com.github.justincranford.springs.util.security.config.SpringsUtilSecurityConfiguration;
import com.github.justincranford.springs.util.security.properties.SpringsUtilSecurityProperties;

import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes={SpringsUtilSecurityConfiguration.class,AbstractIT.AbstractITConfiguration.class})
@AutoConfigureObservability
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@Observed
public class AbstractIT {
    @Autowired
    private ApplicationContext applicationContext;
	@Autowired
	private SpringsUtilSecurityProperties springsUtilSecurityProperties;

    @Configuration
	@EnableAutoConfiguration
	public static class AbstractITConfiguration {
    	// do nothing
    }
}
