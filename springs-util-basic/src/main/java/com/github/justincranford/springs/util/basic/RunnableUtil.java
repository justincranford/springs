package com.github.justincranford.springs.util.basic;

import java.time.Duration;

public class RunnableUtil {
	public static void delayedRun(final Duration sleep, final Runnable runnable) {
		try {
			Thread.sleep(sleep);
		} catch (InterruptedException ie) {
			throw new RuntimeException(ie);
		} finally {
			runnable.run();
		}
	}
}
