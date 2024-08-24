package com.github.justincranford.springs.util.security.hashes;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import com.github.justincranford.springs.util.security.hashes.config.SpringsUtilSecurityHashesConfiguration;
import com.github.justincranford.springs.util.security.hashes.encoder.config.EncodersConfiguration;
import com.github.justincranford.springs.util.security.hashes.encoder.model.KeyEncoders;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ValueEncoders;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties;

import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes={SpringsUtilSecurityHashesConfiguration.class,AbstractIT.AbstractITConfiguration.class})
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
	private SpringsUtilSecurityHashesProperties springsUtilSecurityHashesProperties;
	@Autowired
	private EncodersConfiguration encodersConfiguration;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private KeyEncoders keyEncoders;
	@Autowired
	private ValueEncoders valueEncoders;

    @Configuration
	@EnableAutoConfiguration
	public static class AbstractITConfiguration {
    	// do nothing
    }
}
