package com.github.justincranford.springs.service.webauthn.credential.repository;

import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public class UserIdentityRepositoryOrm {
	private final Cache<String, UserIdentityOrm> users = CacheBuilder.newBuilder()
		.maximumSize(1000)
		.expireAfterAccess(1, TimeUnit.DAYS)
		.build();

    public boolean insert(final UserIdentityOrm userIdentityOrm) {
        if (this.users.getIfPresent(userIdentityOrm.username()) == null) {
        	this.users.put(userIdentityOrm.username(), userIdentityOrm);
            return true;
        }
        return false;
    }
	public UserIdentityOrm read(final String username) {
	    return this.users.getIfPresent(username);
	}
    public boolean update(final UserIdentityOrm userIdentityOrm) {
        if (this.users.getIfPresent(userIdentityOrm.username()) != null) {
        	this.users.put(userIdentityOrm.username(), userIdentityOrm);
            return true;
        }
        return false;
    }
	public void delete(final String username) {
		this.users.invalidate(username);
	}
	public boolean exists(final String username) {
	    return this.users.getIfPresent(username) != null;
	}
    public void upsert(final UserIdentityOrm userIdentityOrm) {
    	this.users.put(userIdentityOrm.username(), userIdentityOrm);
	}
}