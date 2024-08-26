package com.github.justincranford.springs.util.basic;

import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinWorkerThread;
import java.util.concurrent.atomic.AtomicInteger;

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
}
