package com.github.justincranford.springs.persistenceorm.sessions.database.util;

import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class AuthorityUtils {
	public static List<SimpleGrantedAuthority> createAuthorityList(final String authority) {
		return List.of(new SimpleGrantedAuthority(authority));
	}
}
