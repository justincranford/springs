package com.github.justincranford.springs.util.security.passwords;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;

import com.github.justincranford.springs.util.security.passwords.config.SpringsUtilSecurityPasswordsConfiguration;
import com.github.justincranford.springs.util.security.passwords.generator.PasswordGenerator;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;
import com.github.justincranford.springs.util.security.passwords.validator.PasswordValidator;

import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes={SpringsUtilSecurityPasswordsConfiguration.class,AbstractIT.AbstractITConfiguration.class})
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
	private SpringsUtilSecurityPasswordsProperties springsUtilSecurityHashesProperties;
	@Autowired
	private PasswordGenerator usersPasswordGenerator;
	@Autowired
	private PasswordGenerator clientsPasswordGenerator;
	@Autowired
	private PasswordGenerator serversPasswordGenerator;
	@Autowired
	private PasswordGenerator defaultsPasswordGenerator;
	@Autowired
	private PasswordValidator usersPasswordValidator;
	@Autowired
	private PasswordValidator clientsPasswordValidator;
	@Autowired
	private PasswordValidator serversPasswordValidator;
	@Autowired
	private PasswordValidator defaultsPasswordValidator;

	@Configuration
	@EnableAutoConfiguration
	public static class AbstractITConfiguration {
    	// do nothing
    }
}
