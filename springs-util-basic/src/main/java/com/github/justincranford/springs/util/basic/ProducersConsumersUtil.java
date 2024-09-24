package com.github.justincranford.springs.util.basic;

import java.time.Duration;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;

@SuppressWarnings({"nls"})
public class ProducersConsumersUtil {
	@SuppressWarnings("resource")
	public static <T> Runnable run(
		final ExecutorService  executor,
		final int              numProducers,
		final Supplier<T>      producerSupplier,
		final int              numConsumers,
		final BlockingQueue<T> consumerQueue,
		final Consumer<T>      consumerFunction,
	    final Duration         waitForGracefulShutdown
	) {
		final AtomicInteger producedTotal = new AtomicInteger(0);
    	final AtomicInteger consumedTotal = new AtomicInteger(0);
		final AtomicBoolean stop          = new AtomicBoolean(false);

//		System.out.println("Starting producers...");
		final Runnable producerRunnable = producerRunnable(producerSupplier, consumerQueue, stop, producedTotal);
        for (int i = 0; i < numProducers; i++) {
			executor.submit(producerRunnable);
        }

//        System.out.println("Starting consumers...");
        final Runnable consumerRunnable = consumerRunnable(consumerQueue, consumerFunction, stop, consumedTotal);
        for (int i = 0; i < numConsumers; i++) {
			executor.submit(consumerRunnable);
        }

//        System.out.println("Creating stop...");
        return stop(executor, producedTotal, consumedTotal, stop, waitForGracefulShutdown);
    }

	private static <T> Runnable producerRunnable(final Supplier<T> producerSupplier, final BlockingQueue<T> consumerQueue, final AtomicBoolean stop, final AtomicInteger producedTotal) {
		return () -> {
        	T next = null;
    		while (!stop.get() && !Thread.currentThread().isInterrupted()) {
    		    try {
    		        next = producerSupplier.get();
    		        consumerQueue.put(next);
    			} catch (InterruptedException ie) {
    				if (stop.get()) {
    					System.err.println("Producer interrupted and stop=true");
        			    Thread.currentThread().interrupt();
    					break;
    				}
    				wrap("Producer", ie).printStackTrace(System.err);
    			    Thread.currentThread().interrupt();
    			} catch (Exception e) {
    				wrap("Producer", e).printStackTrace(System.err);
    			} catch (Throwable t) {
    				throw wrap("Producer", t);
    		    } finally {
                	if (next != null) {
        		    	producedTotal.incrementAndGet();
                	}
                	next = null;
    		    }
    		}
//    		System.out.println("Producer " + Thread.currentThread().threadId() + " stopped");
    	};
	}

	private static <T> Runnable consumerRunnable(final BlockingQueue<T> consumerQueue, final Consumer<T> consumerFunction, final AtomicBoolean stop, final AtomicInteger consumedTotal) {
		return () -> {
        	T next = null;
    		while (!stop.get() && !Thread.currentThread().isInterrupted()) {
                try {
                    next = consumerQueue.take();
                    consumerFunction.accept(next);
    			} catch (InterruptedException ie) {
    				if (stop.get()) {
    					System.err.println("Consumer interrupted and stop=true");
        			    Thread.currentThread().interrupt();
    					break;
    				}
    				wrap("Consumer", ie).printStackTrace(System.err);
    			    Thread.currentThread().interrupt();
    			} catch (Exception e) {
    				wrap("Consumer", e).printStackTrace(System.err);
    			} catch (Throwable t) {
    				throw wrap("Consumer", t);
                } finally {
                	if (next != null) {
                    	consumedTotal.incrementAndGet();
                	}
                	next = null;
                }
            }
//    		System.out.println("Consumer " + Thread.currentThread().threadId() + " stopped");
    	};
	}

	private static Runnable stop(
		ExecutorService executor,
		final AtomicInteger producedTotal,
		final AtomicInteger consumedTotal,
		final AtomicBoolean stop,
		final Duration      waitForGracefulShutdown
	) {
		return () -> {
		    try {
//				System.out.println("Set stop flag...");
			    stop.set(true);
//				System.out.println("Requesting graceful shutdown...");
			    executor.shutdown();
//				System.out.println("Waiting for graceful shutdown...");
				executor.awaitTermination(waitForGracefulShutdown.toNanos(), TimeUnit.NANOSECONDS);
			} catch (InterruptedException e) {
				wrap("Stop", e).printStackTrace(System.err);
			    Thread.currentThread().interrupt();
			} catch (Exception e) {
				wrap("Stop", e).printStackTrace(System.err);
			} catch (Throwable t) {
				throw wrap("Stop", t);
			} finally {
				if (executor.isTerminated()) {
					System.out.println("Completed graceful shutdown...");
				} else {
//					System.out.println("Requesting forced shutdown...");
					executor.shutdownNow();
					System.out.println("Completed forced shutdown...");
				}
				System.out.println("Produced " + producedTotal + ", Consumed " + consumedTotal);
	        }
		};
	}

	private static RuntimeException wrap(final String name, Throwable t) {
		return new RuntimeException(name + " " + Thread.currentThread().threadId() + " unrecoverable exception", t);
    }

	private static Exception wrap(final String name, Exception e) {
		return new Exception(name + " " + Thread.currentThread().threadId() + " recoverable exception", e);
	}

	@SuppressWarnings("unused")
	private static void throwRandomException() throws Exception {
		if (new Random().nextBoolean()) {
//			throw new Exception();
//			throw new Throwable();
			throw new InterruptedException();
		}
	}
}
