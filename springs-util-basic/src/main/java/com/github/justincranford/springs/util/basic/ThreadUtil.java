package com.github.justincranford.springs.util.basic;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinWorkerThread;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;
import java.util.function.Supplier;

public class ThreadUtil {
	public static ForkJoinPool threadPool(final int threads, final String threadNamePrefix) {
		final AtomicInteger index = new AtomicInteger(1);
		final ForkJoinPool.ForkJoinWorkerThreadFactory factory = pool -> {
			final ForkJoinWorkerThread worker = ForkJoinPool.defaultForkJoinWorkerThreadFactory.newThread(pool);
			worker.setName(threadNamePrefix + index.getAndIncrement());
			return worker;
		};
		return new ForkJoinPool(threads, factory, null, false);
	}

	public static <T> Future<T> async(final ThrowingSupplier<T> throwingSupplier) {
		return CompletableFuture.supplyAsync(() -> throwingSupplier.get());
	}

	public interface ThrowingSupplier<T> extends Supplier<T> {
		T getWithThrowable() throws Throwable;

		@Override
		default T get() {
			return get(RuntimeException::new);
		}

		default T get(BiFunction<String, Throwable, RuntimeException> exceptionWrapper) {
			try {
				return getWithThrowable();
			} catch (RuntimeException ex) {
				throw ex;
			} catch (Throwable t) {
				throw exceptionWrapper.apply(t.getMessage(), t);
			}
		}
	}
}
