package com.github.justincranford.springs.util.basic;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

public class StringUtil {
	public static String toString(final String prefix, final String delimiter, final String suffix, final Collection<?> objects) {
		return prefix + String.join(delimiter, objects.stream().map(Object::toString).toList()) + suffix;
	}

	public static List<String> split(final String string, final String delimiter) {
        final StringTokenizer tokenizer = new StringTokenizer(string, delimiter);
        final List<String> strings = new LinkedList<>();
        while (tokenizer.hasMoreTokens()) {
        	strings.add(tokenizer.nextToken());
        }
        return strings;
	}
}
