package com.github.justincranford.springs.util.basic;

import java.util.Collection;

@SuppressWarnings("nls")
public class StringUtil {
	public static String toString(final String prefix, final String delimiter, final String suffix, final Collection<?> objects) {
		return prefix + String.join(delimiter, objects.stream().map(Object::toString).toList()) + suffix;
	}
}
