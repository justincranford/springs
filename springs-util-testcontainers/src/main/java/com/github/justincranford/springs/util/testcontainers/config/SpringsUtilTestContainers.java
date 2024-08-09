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

// TODO Make @Observed work
/**
 * Container.start() is blocking, so start containers concurrently
 */
@SuppressWarnings({"nls", "boxing"})
public class SpringsUtilTestContainers {
    private static List<AbstractTestContainer<?>> ALL_TEST_CONTAINER_INSTANCES;

	private static List<AbstractTestContainer<?>> allTestContainerInstances() {
		return List.of(
//		    new TestContainerElasticsearch(),  // Example: 23.152 seconds 47.656 seconds
//		    new TestContainerKeycloak(),       // Example: 18.809 seconds 40.408 seconds
//		    new TestContainerGrafana(),        // Example: 10.437 seconds 17.041 seconds
//		    new TestContainerKafka(),          // Example:  8.321 seconds 15.380 seconds
//		    new TestContainerZipkin(),         // Example:  6.794 seconds 17.291 seconds
//		    new TestContainerDynamoDb(),       // Example:  6.300 seconds 11.433 seconds
//		    new TestContainerPostgresql(),     // Example:  6.204 seconds  4.056 seconds
//		    new TestContainerSeleniumChrome(), // Example:  5.468 seconds  7.835 seconds
//		    new TestContainerMongoDb(),        // Example:  5.060 seconds  7.026 seconds
//		    new TestContainerVault(),          // Example:  3.640 seconds  2.909 seconds
//		    new TestContainerConsul(),         // Example:  2.602 seconds  2.933 seconds
//		    new TestContainerRedis(),          // Example:  2.334 seconds  2.647 seconds
//		    new TestContainerOllama()          // Example:  1.318 seconds  1.936 seconds
		);
	}

    @Observed
    public static synchronized void startAllContainers() {
    	if (ALL_TEST_CONTAINER_INSTANCES != null) {
            System.out.println("Already started");
    	} else {
    		ALL_TEST_CONTAINER_INSTANCES = allTestContainerInstances();
            startContainers(ALL_TEST_CONTAINER_INSTANCES);
    	}
    }

    @Observed
    public static synchronized void stopAllContainers() {
    	if (ALL_TEST_CONTAINER_INSTANCES != null) {
            stopContainers(ALL_TEST_CONTAINER_INSTANCES);
            ALL_TEST_CONTAINER_INSTANCES = null;
    	} else {
            System.out.println("Not started");
    	}
    }

    @Observed
    public static void startContainers(final List<AbstractTestContainer<?>> testContainerInstances) {
        final long startNanos = System.nanoTime();
        try {
            System.out.println(String.format("Starting containers, count: %s", testContainerInstances.size()));
            testContainerInstances.parallelStream().forEach(testContainerInstance -> startContainer(testContainerInstance));
        } finally {
            System.out.println(String.format("Started containers, count: %s, duration: %s", testContainerInstances.size(), format(startNanos)));
        }
    }

    @Observed
    public static void stopContainers(final List<AbstractTestContainer<?>> testContainerInstances) {
        final long startNanos = System.nanoTime();
        try {
            System.out.println(String.format("Stopping containers, count: %s", ALL_TEST_CONTAINER_INSTANCES.size()));
            testContainerInstances.parallelStream().forEach(testContainerInstance -> stopContainer(testContainerInstance));
        } finally {
            System.out.println(String.format("Stopped containers, count: %s, duration: %s", ALL_TEST_CONTAINER_INSTANCES.size(), format(startNanos)));
        }
    }

    @Observed
    private static boolean startContainer(final AbstractTestContainer<?> testContainerInstance) {
        final long startNanos = System.nanoTime();
		final boolean isStarted = testContainerInstance.isRunning();
        if (isStarted) {
            System.out.println(String.format("Already started container, image name: %s", testContainerInstance.getContainerName()));
        } else {
            final GenericContainer<?> genericContainer = testContainerInstance.initAndGetInstance();
        	try {
                System.out.println(String.format("Starting container, image name: %s", testContainerInstance.getContainerName()));
                genericContainer.start();
            } catch(Throwable t) {
                System.out.println(String.format("Start container failed, image name: %s, duration: %s", testContainerInstance.getContainerName(), format(startNanos)));
            } finally {
                System.out.println(String.format("Started container, image name: %s, duration: %s", testContainerInstance.getContainerName(), format(startNanos)));
            }
        }
        return isStarted;
    }

    @Observed
    private static boolean stopContainer(final AbstractTestContainer<?> testContainerInstance) {
        final long startNanos = System.nanoTime();
        final boolean isStopped = !testContainerInstance.isRunning();
        if (isStopped) {
            System.out.println(String.format("Already stopped container, image name: %s", testContainerInstance.getContainerName()));
        } else {
            try {
                final GenericContainer<?> genericContainer = testContainerInstance.getInstance();
                System.out.println(String.format("Stopping container, image name: %s", testContainerInstance.getContainerName()));
                genericContainer.stop();
            } catch(Throwable t) {
                System.out.println(String.format("Stop container failed, image name: %s, duration: %s", testContainerInstance.getContainerName(), format(startNanos)));
            } finally {
                System.out.println(String.format("Stopped container, image name: %s, duration: %s", testContainerInstance.getContainerName(), format(startNanos)));
            }
        }
        return isStopped;
    }

    private static String format(final long startNanos) {
        return Duration.ofNanos(System.nanoTime() - startNanos).truncatedTo(ChronoUnit.MILLIS).toMillis()/1000F + " seconds";
    }
}
