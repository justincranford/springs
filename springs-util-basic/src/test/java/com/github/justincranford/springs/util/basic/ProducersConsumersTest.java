package com.github.justincranford.springs.util.basic;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestClassOrder;
import org.junit.jupiter.api.TestMethodOrder;

@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SuppressWarnings({"nls", "static-method"})
public class ProducersConsumersTest {
	private static record UtcAndI18nLog(OffsetDateTime utc, I18nLog log) {}
	private static record I18nLog(String tag, List<Object> args) {}

	private static final Duration DELAY_BEFORE_TRIGGERING_STOP = Duration.ofMillis(500);
	private static final Duration WAIT_FOR_GRACEFUL_SHUTDOWN = Duration.ofMillis(100);

	@Order(1)
	@Nested
	public class FixedThreadPool {
		@Order(1)
		@Test
	    void testSerialized() {
	    	try (final ExecutorService executor = Executors.newFixedThreadPool(2)) {
	    		helper(executor, 1, 1, 1, DELAY_BEFORE_TRIGGERING_STOP, WAIT_FOR_GRACEFUL_SHUTDOWN);
			}
		}


		@Order(2)
		@Test
	    void testSmall() {
	    	try (final ExecutorService executor = Executors.newFixedThreadPool(3)) {
	    		helper(executor, 100, 1, 2, DELAY_BEFORE_TRIGGERING_STOP, WAIT_FOR_GRACEFUL_SHUTDOWN);
			}
		}

		@Order(3)
		@Test
		void testMedium() {
	    	try (final ExecutorService executor = Executors.newFixedThreadPool(6)) {
	    		helper(executor, 1_000, 2, 4, DELAY_BEFORE_TRIGGERING_STOP, WAIT_FOR_GRACEFUL_SHUTDOWN);
			}
		}

		@Order(4)
		@Test
		void testLarge() {
	    	try (final ExecutorService executor = Executors.newFixedThreadPool(12)) {
	    		helper(executor, 10_000, 4, 8, DELAY_BEFORE_TRIGGERING_STOP, WAIT_FOR_GRACEFUL_SHUTDOWN);
			}
		}
	}

	@Order(2)
	@Nested
	public class VirtualThreadPerTask {
		@Order(1)
		@Test
	    void testSerialized() {
	    	try (final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
	    		helper(executor, 1, 1, 1, DELAY_BEFORE_TRIGGERING_STOP, WAIT_FOR_GRACEFUL_SHUTDOWN);
			}
		}

		@Order(2)
		@Test
	    void testSmall() {
	    	try (final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
	    		helper(executor, 100, 1, 2, DELAY_BEFORE_TRIGGERING_STOP, WAIT_FOR_GRACEFUL_SHUTDOWN);
			}
		}

		@Order(3)
		@Test
		void testMedium() {
	    	try (final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
	    		helper(executor, 1_000, 2, 4, DELAY_BEFORE_TRIGGERING_STOP, WAIT_FOR_GRACEFUL_SHUTDOWN);
			}
		}

		@Order(4)
		@Test
		void testLarge() {
	    	try (final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
	    		helper(executor, 10_000, 4, 8, DELAY_BEFORE_TRIGGERING_STOP, WAIT_FOR_GRACEFUL_SHUTDOWN);
			}
		}
	}

	private void helper(final ExecutorService executor, final int consumerQueueSize, final int numProducers, final int numConsumers, final Duration stopDelay, final Duration shutdownWait) {
		final Map<OffsetDateTime, List<I18nLog>> logs = new ConcurrentSkipListMap<>();

		final AtomicInteger           producerIndex    = new AtomicInteger(1);
		final Supplier<UtcAndI18nLog> producerSupplier = () -> new UtcAndI18nLog(
			DateTimeUtil.nowUtcTruncatedToMicroseconds(),
			new I18nLog(
				"msg." + SecureRandomUtil.SECURE_RANDOM.nextInt(1000, 2000),
				List.of(Long.valueOf(producerIndex.getAndIncrement()))
			)
		);
		final BlockingQueue<UtcAndI18nLog> consumerQueue    = new LinkedBlockingQueue<>(consumerQueueSize);
		final Consumer<UtcAndI18nLog>      consumerFunction = (utcI18n) -> 
			logs.compute(utcI18n.utc(), (utc, existingList) -> {
				synchronized(logs) {
					final List<I18nLog> list = (existingList == null) ? new ArrayList<>() : existingList;
				    list.add(utcI18n.log());
				    return list;
				}
			});

		final Runnable stop = ProducersConsumersUtil.run(executor, numProducers, producerSupplier, numConsumers, consumerQueue, consumerFunction, shutdownWait);
		RunnableUtil.delayedRun(stopDelay, stop);

		System.out.println("Unique time stamps: " + logs.size() + ", Log lists stats: " + logs.values().stream().mapToInt(List::size).summaryStatistics() + "\n");
	}
}
