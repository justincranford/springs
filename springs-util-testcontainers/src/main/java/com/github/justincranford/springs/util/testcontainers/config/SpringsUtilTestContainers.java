package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.testcontainers.containers.GenericContainer;

import com.github.justincranford.springs.util.testcontainers.containers.AbstractTestContainer;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerConsul;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerDynamoDb;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerElasticsearch;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerGrafana;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerKafka;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerKeycloak;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerMongoDb;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerOllama;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerPostgresql;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerRedis;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerSeleniumChrome;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerVault;
import com.github.justincranford.springs.util.testcontainers.containers.TestContainerZipkin;

import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;

/**
 * Container.start() is blocking, so start multiple containers concurrently. Same for stop.
 */
@Slf4j
@SuppressWarnings({"nls", "boxing", "resource"})
public class SpringsUtilTestContainers {
	public static final TestContainerElasticsearch  ELASTICSEARCH  = new TestContainerElasticsearch();
	public static final TestContainerKeycloak       KEYCLOCK       = new TestContainerKeycloak();
	public static final TestContainerGrafana        GRAFANA        = new TestContainerGrafana();
	public static final TestContainerKafka          KAFKA          = new TestContainerKafka();
	public static final TestContainerZipkin         ZIPKIN         = new TestContainerZipkin();
	public static final TestContainerDynamoDb       DYNAMODB       = new TestContainerDynamoDb();
	public static final TestContainerPostgresql     POSTGRESQL     = new TestContainerPostgresql();
	public static final TestContainerSeleniumChrome SELENIUMCHROME = new TestContainerSeleniumChrome();
	public static final TestContainerMongoDb        MONGODB        = new TestContainerMongoDb();
	public static final TestContainerVault          VAULT          = new TestContainerVault();
	public static final TestContainerConsul         CONSUL         = new TestContainerConsul();
	public static final TestContainerRedis          REDIS          = new TestContainerRedis();
	public static final TestContainerOllama         OLLAMA         = new TestContainerOllama();

	public static final List<AbstractTestContainer<?>> ALL = List.of(
	    ELASTICSEARCH,  // Example: 23.152 seconds 47.656 seconds
	    KEYCLOCK,       // Example: 18.809 seconds 40.408 seconds
	    GRAFANA,        // Example: 10.437 seconds 17.041 seconds
	    KAFKA,          // Example:  8.321 seconds 15.380 seconds
	    ZIPKIN,         // Example:  6.794 seconds 17.291 seconds
	    DYNAMODB,       // Example:  6.300 seconds 11.433 seconds
	    POSTGRESQL,     // Example:  6.204 seconds  4.056 seconds
	    SELENIUMCHROME, // Example:  5.468 seconds  7.835 seconds
	    MONGODB,        // Example:  5.060 seconds  7.026 seconds
	    VAULT,          // Example:  3.640 seconds  2.909 seconds
	    CONSUL,         // Example:  2.602 seconds  2.933 seconds
	    REDIS,          // Example:  2.334 seconds  2.647 seconds
	    OLLAMA          // Example:  1.318 seconds  1.936 seconds
	);

    @Observed
    public static synchronized void startAllContainers() {
        startContainers(ALL);
    }

    @Observed
    public static synchronized void stopAllContainers() {
        stopContainers(ALL);
    }

    @Observed
    public static void startContainers(final List<AbstractTestContainer<?>> testContainerInstances) {
        final long startNanos = System.nanoTime();
        try {
            log.debug("Starting containers, count: {}", testContainerInstances.size());
            testContainerInstances.parallelStream().forEach(testContainerInstance -> startContainer(testContainerInstance));
        } finally {
            log.debug("Started containers, count: {}, duration: {}", testContainerInstances.size(), format(startNanos));
        }
    }

    @Observed
    public static void stopContainers(final List<AbstractTestContainer<?>> testContainerInstances) {
        final long startNanos = System.nanoTime();
        try {
            log.debug("Stopping containers, count: {}", testContainerInstances.size());
            testContainerInstances.parallelStream().forEach(testContainerInstance -> stopContainer(testContainerInstance));
        } finally {
            log.debug("Stopped containers, count: {}, duration: {}", testContainerInstances.size(), format(startNanos));
        }
    }

	@Observed
    public static void startContainer(final AbstractTestContainer<?> testContainerInstance) {
        final long startNanos = System.nanoTime();
        final GenericContainer<?> genericContainer = testContainerInstance.getInstance();
    	try {
    		final boolean isStarted = genericContainer.isRunning();
            if (isStarted) {
                log.debug("Already started container, image name: {}", testContainerInstance.getContainerName());
            } else {
                log.debug("Starting container, image name: {}", testContainerInstance.getContainerName());
                genericContainer.start();
            }
        } catch(Throwable t) {
            log.debug("Start container failed, image name: {}, duration: {}", testContainerInstance.getContainerName(), format(startNanos), t);
        } finally {
            log.debug("Started container, image name: {}, duration: {}", testContainerInstance.getContainerName(), format(startNanos));
        }
    }

    @Observed
    public static void stopContainer(final AbstractTestContainer<?> testContainerInstance) {
        final long startNanos = System.nanoTime();
        final GenericContainer<?> genericContainer = testContainerInstance.getInstance();
        try {
            final boolean isStopped = !genericContainer.isRunning();
            if (isStopped) {
                log.debug("Already stopped container, image name: {}", testContainerInstance.getContainerName());
            } else {
                log.debug("Stopping container, image name: {}", testContainerInstance.getContainerName());
                genericContainer.stop();
            }
        } catch(Throwable t) {
            log.debug("Stop container failed, image name: {}, duration: {}", testContainerInstance.getContainerName(), format(startNanos), t);
        } finally {
            log.debug("Stopped container, image name: {}, duration: {}", testContainerInstance.getContainerName(), format(startNanos));
        }
    }

    private static String format(final long startNanos) {
        return Duration.ofNanos(System.nanoTime() - startNanos).truncatedTo(ChronoUnit.MILLIS).toMillis()/1000F + " seconds";
    }
}
