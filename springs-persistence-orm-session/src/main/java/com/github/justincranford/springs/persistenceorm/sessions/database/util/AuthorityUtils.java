package com.github.justincranford.springs.persistenceorm.sessions.database.util;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

@SuppressWarnings({"unused"})
public class AuthorityUtils {
    public static List<SimpleGrantedAuthority> createAuthorityList(final String authority) {
        return List.of(new SimpleGrantedAuthority(authority));
    }
}
