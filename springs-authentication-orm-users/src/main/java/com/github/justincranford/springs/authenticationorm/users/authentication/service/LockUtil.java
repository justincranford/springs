package com.github.justincranford.springs.authenticationorm.users.authentication.service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import org.springframework.stereotype.Component;

import com.github.justincranford.springs.util.basic.Timer;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class LockUtil<KEY, RETURN_TYPE> {
    private final ConcurrentHashMap<KEY, ReentrantLock> locks = new ConcurrentHashMap<>();

    public RETURN_TYPE run(final KEY key, final Supplier<RETURN_TYPE> supplier) {
        final ReentrantLock lock = lock(key);
        try {
        	return supplier.get();
        } finally {
    		unlock(key, lock);
        }
	}

	private ReentrantLock lock(final KEY key) {
		final ReentrantLock lock;
		try (Timer x = Timer.go("locks.computeIfAbsent")) {
			try (Timer y = Timer.go("locks.computeIfAbsent/" + key)) {
				lock = this.locks.computeIfAbsent(key, newKey -> new ReentrantLock());
			}
		}
		log.trace("Locking [{}]", key);
		try (Timer x = Timer.go("locks.lock")) {
			try (Timer y = Timer.go("locks.lock/" + key)) {
		        lock.lock();
			}
		}
		log.trace("Locked [{}]", key);
		return lock;
	}

	private void unlock(final KEY key, final ReentrantLock lock) {
		log.trace("Unlocking [{}]", key);
		try (Timer x = Timer.go("locks.unlock")) {
			try (Timer y = Timer.go("locks.unlock/" + key)) {
				lock.unlock();
			}
		}
		log.trace("Unlocked [{}]", key);
		try (Timer x = Timer.go("locks.remove")) {
			try (Timer y = Timer.go("locks.remove/" + key)) {
				this.locks.remove(key, lock);
			}
		}
		log.trace("Removed [{}]", key);
	}
}
