package com.github.justincranford.springs.util.basic.util;

import java.util.Collection;

public class StringUtil {
	public static String toString(final String prefix, final String delimiter, final String suffix, final Collection<?> objects) {
		return prefix + String.join(delimiter, objects.stream().map(Object::toString).toList()) + suffix;
	}
}
