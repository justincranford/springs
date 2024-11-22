package com.github.justincranford.springs.util.testcontainers;

import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainersApplicationContextInitializer;
import com.github.justincranford.springs.util.testcontainers.containers.AbstractTestContainer;
import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

@EnableAutoConfiguration
@SpringBootTest(classes={AbstractIT.AbstractITConfiguration.class})
@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@Observed
@SuppressWarnings({"static-method"})
public class AbstractIT {
	@Autowired
    private ApplicationContext applicationContext;

	protected void verifyStopped(final AbstractTestContainer<?> testContainer) {
		assertThat(testContainer).isNotNull();
		assertThat(testContainer.getInstance()).isNotNull();
		assertThat(testContainer.getInstance().isRunning()).isFalse();
	}

	protected void verifyStarted(final AbstractTestContainer<?> testContainer) {
		assertThat(testContainer).isNotNull();
		assertThat(testContainer.getInstance()).isNotNull();
		assertThat(testContainer.getInstance().isRunning()).isTrue();
		assertThat(testContainer.getInstance().getHost()).isNotNull();
		assertThat(testContainer.getInstance().getFirstMappedPort()).isNotNull();
		assertThat(testContainer.getInstance().getContainerName()).isNotNull();
		log.info("Host: {}, Port: {}, Name: {}", testContainer.getInstance().getHost(), testContainer.getInstance().getFirstMappedPort(), testContainer.getContainerName());
	}

	@Configuration
	public static class AbstractITConfiguration {
		// Empty
	}
}
