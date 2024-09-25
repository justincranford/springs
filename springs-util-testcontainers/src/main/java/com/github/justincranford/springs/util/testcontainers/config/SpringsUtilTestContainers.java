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

// TODO Make @Observed work
/**
 * Container.start() is blocking, so start containers concurrently
 */
@Slf4j
@SuppressWarnings({"nls", "boxing"})
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
//		    ELASTICSEARCH,  // Example: 23.152 seconds 47.656 seconds
//		    KEYCLOCK,       // Example: 18.809 seconds 40.408 seconds
//		    GRAFANA,        // Example: 10.437 seconds 17.041 seconds
//		    KAFKA,          // Example:  8.321 seconds 15.380 seconds
//		    ZIPKIN,         // Example:  6.794 seconds 17.291 seconds
//		    DYNAMODB,       // Example:  6.300 seconds 11.433 seconds
//		    POSTGRESQL,     // Example:  6.204 seconds  4.056 seconds
//		    SELENIUMCHROME, // Example:  5.468 seconds  7.835 seconds
//		    MONGODB,        // Example:  5.060 seconds  7.026 seconds
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
            log.info("Starting containers, count: {}", testContainerInstances.size());
            testContainerInstances.parallelStream().forEach(testContainerInstance -> startContainer(testContainerInstance));
        } finally {
            log.info("Started containers, count: {}, duration: {}", testContainerInstances.size(), format(startNanos));
        }
    }

    @Observed
    public static void stopContainers(final List<AbstractTestContainer<?>> testContainerInstances) {
        final long startNanos = System.nanoTime();
        try {
            log.info("Stopping containers, count: {}", testContainerInstances.size());
            testContainerInstances.parallelStream().forEach(testContainerInstance -> stopContainer(testContainerInstance));
        } finally {
            log.info("Stopped containers, count: {}, duration: {}", testContainerInstances.size(), format(startNanos));
        }
    }

    @Observed
    public static boolean startContainer(final AbstractTestContainer<?> testContainerInstance) {
        final long startNanos = System.nanoTime();
		final boolean isStarted = testContainerInstance.isRunning();
        if (isStarted) {
            log.info("Already started container, image name: {}", testContainerInstance.getContainerName());
        } else {
        	try (final GenericContainer<?> genericContainer = testContainerInstance.initAndGetInstance()) {
                log.info("Starting container, image name: {}", testContainerInstance.getContainerName());
                genericContainer.start();
            } catch(Throwable t) {
                log.info("Start container failed, image name: {}, duration: {}", testContainerInstance.getContainerName(), format(startNanos), t);
            } finally {
                log.info("Started container, image name: {}, duration: {}", testContainerInstance.getContainerName(), format(startNanos));
            }
        }
        return isStarted;
    }

    @Observed
    public static boolean stopContainer(final AbstractTestContainer<?> testContainerInstance) {
        final long startNanos = System.nanoTime();
        final boolean isStopped = !testContainerInstance.isRunning();
        if (isStopped) {
            log.info("Already stopped container, image name: {}", testContainerInstance.getContainerName());
        } else {
            try (final GenericContainer<?> genericContainer = testContainerInstance.getInstance()) {
                log.info("Stopping container, image name: {}", testContainerInstance.getContainerName());
                genericContainer.stop();
            } catch(Throwable t) {
                log.info("Stop container failed, image name: {}, duration: {}", testContainerInstance.getContainerName(), format(startNanos), t);
            } finally {
                log.info("Stopped container, image name: {}, duration: {}", testContainerInstance.getContainerName(), format(startNanos));
            }
        }
        return isStopped;
    }

    private static String format(final long startNanos) {
        return Duration.ofNanos(System.nanoTime() - startNanos).truncatedTo(ChronoUnit.MILLIS).toMillis()/1000F + " seconds";
    }
}
