package com.github.justincranford.springs.persistenceredis.sessions.database.util;

import java.util.List;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class AuthorityUtils {
	public static List<SimpleGrantedAuthority> createAuthorityList(final String authority) {
		return List.of(new SimpleGrantedAuthority(authority));
	}
}
