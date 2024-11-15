package com.github.justincranford.springs.persistenceorm.sessions.database.util;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class AuthorityUtils {
	public static List<CustomGrantedAuthority> createAuthorityList(final String authority) {
		return List.of(new CustomGrantedAuthority(authority));
	}
}
