package com.github.justincranford.springs.util.certs;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

import com.github.justincranford.springs.util.certs.tls.TomcatTlsInitializer;

import lombok.Getter;
import lombok.experimental.Accessors;

@SpringBootTest(
	classes={AbstractIT.AbstractITConfiguration.class},
	webEnvironment = WebEnvironment.RANDOM_PORT
)
@ContextConfiguration(
	initializers={TomcatTlsInitializer.class}
)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
public class AbstractIT {
    @EnableAutoConfiguration(exclude = { UserDetailsServiceAutoConfiguration.class })
    @EnableConfigurationProperties
    static class AbstractITConfiguration {
    	// do nothing
    }
}
