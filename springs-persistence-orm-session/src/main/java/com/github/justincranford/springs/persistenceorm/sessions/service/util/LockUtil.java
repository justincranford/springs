package com.github.justincranford.springs.persistenceorm.sessions.service.util;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import org.springframework.stereotype.Component;

import com.github.justincranford.springs.util.basic.Timer;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class LockUtil<KEY, VALUE> {
    private final ConcurrentHashMap<KEY, ReentrantLock> locks = new ConcurrentHashMap<>();

    public VALUE run(final KEY key, final Supplier<VALUE> supplier) {
        final ReentrantLock lock = lock(key);
        try {
        	return supplier.get();
        } finally {
    		unlock(key, lock);
        }
	}

	private ReentrantLock lock(final KEY key) {
		final ReentrantLock lock;
		try (Timer ignored = Timer.go("locks.computeIfAbsent", "locks.computeIfAbsent_" + key)) {
			lock = this.locks.computeIfAbsent(key, newKey -> new ReentrantLock());
		}
		log.trace("Locking [{}]", key);
		try (Timer ignored = Timer.go("locks.lock", "locks.lock_" + key)) {
	        lock.lock();
		}
		log.trace("Locked [{}]", key);
		return lock;
	}

	private void unlock(final KEY key, final ReentrantLock lock) {
		log.trace("Unlocking [{}]", key);
		try (Timer ignored = Timer.go("locks.unlock", "locks.unlock_" + key)) {
			lock.unlock();
		}
		log.trace("Unlocked [{}]", key);
		try (Timer ignored = Timer.go("locks.remove", "locks.remove_" + key)) {
			this.locks.remove(key, lock);
		}
		log.trace("Removed [{}]", key);
	}
}
