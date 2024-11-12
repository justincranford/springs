package com.github.justincranford.springs.authenticationorm.users.authentication.service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class LockUtil<RETURN_TYPE> {
    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    public RETURN_TYPE run(final String key, final Supplier<RETURN_TYPE> supplier) {
        final ReentrantLock lock = this.locks.computeIfAbsent(key, newKey -> new ReentrantLock());
		log.trace("Locking [{}]", key);
        lock.lock();
        try {
    		log.trace("Locked [{}]", key);
        	return supplier.get();
        } finally {
    		log.trace("Unlocking [{}]", key);
            lock.unlock();
    		log.trace("Unlocked [{}]", key);
            this.locks.remove(key, lock);
        }
	}
}
