package com.github.justincranford.springs.persistenceorm.sessions.database.util;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class CustomGrantedAuthority implements GrantedAuthority {
	private static final long serialVersionUID = 1L;

	private String authority;

	public CustomGrantedAuthority() {
		this.authority = null;
	}

	public CustomGrantedAuthority(String _authority) {
		Assert.hasText(_authority, "A granted authority textual representation is required");
		this.authority = _authority;
	}

	@Override
	public String getAuthority() {
		return this.authority;
	}

	public void setAuthority(final String _authority) {
		this.authority = _authority;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj instanceof CustomGrantedAuthority sga) {
			return this.authority.equals(sga.getAuthority());
		}
		return false;
	}

	@Override
	public int hashCode() {
		return this.authority.hashCode();
	}

	@Override
	public String toString() {
		return this.authority;
	}
}
